import re
import os
import sys
import ast
import json
import argparse
import subprocess

from neo4j import GraphDatabase

PROJECT_ROOT = os.path.join(os.path.dirname(sys.argv[0]), f'..{os.path.sep}..')
sys.path.append(PROJECT_ROOT)

import constants
from utils.utility import _hash

from hpg_analysis.general.control_flow import do_reachability_analysis
from hpg_analysis.general.data_flow import get_varname_value_from_context

from hpg_analysis.dom_clobbering.const import WINDOW_PREDEFINED_PROPERTIES

from hpg_neo4j.db_utility import API_neo4j_prepare
from hpg_neo4j.query_utility import getChildsOf, get_code_expression


DEBUG = False

CLOBBERING_REGEX = re.compile('window\.(?!(%s)(;|\s)).*' % '|'.join(WINDOW_PREDEFINED_PROPERTIES))
SCRIPT_REGEX = re.compile('document\.createElement\([\'|"](script)[\'|"]\)')


def get_property_assignment_sinks(tx, property, obj=None):

    obj_slice = ''
    if obj is not None:
        obj_slice = ',\n(left_expr)-[:AST_parentOf*1..5 {RelationType: "object"}]->(object_node {Type: "Identifier", Code: "%s"})' % obj

    query = '''MATCH (expr_node {Type: "ExpressionStatement"})-[:AST_parentOf {RelationType: "expression"}]->(assign_expr {Type: "AssignmentExpression"}),
                (assign_expr)-[:AST_parentOf {RelationType: "right"}]->(right_expr),
                (assign_expr)-[:AST_parentOf {RelationType: "left"}]->(left_expr {Type: "MemberExpression"}),
                (left_expr)-[:AST_parentOf {RelationType: "property"}]->(property_node {Type: "Identifier", Code: "%s"})%s
        WHERE right_expr.Type = 'Identifier' OR right_expr.Type = 'MemberExpression'
        RETURN expr_node, assign_expr, right_expr;''' % (property, obj_slice)

    if DEBUG: print(query)

    return [(r['expr_node'], r['assign_expr'], get_top_obj(tx, r['right_expr'])) for r in tx.run(query)]


def get_complex_call_sinks(tx, n_args, func, obj=None):

    results = []

    arg_node_query_slices = ''
    arg_node_returns = ''
    for i in range(0, n_args):
        arg_node_query_slices += '\n(call_expr)-[:AST_parentOf {RelationType: "arguments", Arguments: \'{"arg":%d}\'}]->(arg_node_%d),' % (i, i)
        arg_node_returns += ', arg_node_%d' % i

    callee_props = '{Type: "Identifier", Code: "%s"}' % func
    callee_locator = ''
    callee_where = ''
    if obj is not None:
        callee_props = '{Type: "MemberExpression"}'
        callee_locator = ''',
            (callee_node)-[:AST_parentOf {RelationType: "property"}]->({Type: "Identifier", Code: "%s"}),
            (callee_node)-[obj_rels:AST_parentOf*1..5]->({Type: "Identifier", Code: "%s"})
        ''' % (func, obj)
        or_clause = ' OR obj_rel.RelationType = "callee"' if obj == '$' else ''
        callee_where = ' AND ALL (obj_rel IN obj_rels WHERE obj_rel.RelationType = "object"%s)' % or_clause

    query = '''MATCH (expr_node)-[:AST_parentOf*1..10]->(call_expr {Type: "CallExpression"}),%s
            (call_expr)-[:AST_parentOf {RelationType: "callee"}]->(callee_node %s)%s
        WHERE expr_node.Type = 'ExpressionStatement' OR expr_node.Type = 'VariableDeclaration'%s
        RETURN expr_node, call_expr%s;
    ''' % (arg_node_query_slices, callee_props, callee_locator, callee_where, arg_node_returns)

    if DEBUG: print(query)

    for result in tx.run(query):
        expr_node = result['expr_node']
        call_expr = result['call_expr']
        for i in range(0, n_args):
            arg = get_top_obj(tx, result['arg_node_%d' % i])
            if arg and arg['Type'] == 'Identifier':
                results.append((expr_node, call_expr, arg))
            
    return results


def get_top_obj(tx, node):
    if node['Type'] == 'Identifier':
        return node
    results = tx.run('MATCH ({Id: "%s"})-[:AST_parentOf*1..10 {RelationType: "object"}]->(top {Type: "Identifier"}) RETURN top;' % node['Id'])
    for result in results:
        return result['top']
    return None


def parse_location(location_str):
    location_regex = re.match('{start:{line:([0-9]+),column:([0-9]+)},end:{line:([0-9]+),column:([0-9]+)}}', location_str)
    start_line, start_col, end_line, end_col = location_regex.groups()
    return {
        'start_line': start_line, 
        'start_col': start_col, 
        'end_line': end_line, 
        'end_col': end_col
    }


def report_out(file_handle, text):
    if file_handle:
        file_handle.write(text)
        file_handle.flush()
    print(text)

def generate_report(vulnerabilities, out_path=None, report_json=True):

    file_handle = None if not out_path else open(out_path, 'w')

    if report_json:
        json_repr = json.dumps(vulnerabilities, indent = 4)
        report_out(file_handle, json_repr)

    else:
        vulnerability_count = 1
        for vulnerability in vulnerabilities:

            loc = vulnerability['location']
            loc_str = f"{loc['start_line']}:{loc['start_col']}"

            report_readable = f'''
[*] Tags: {repr(vulnerability['tags'])}
[*] NodeId: {repr(vulnerability['node_id'])}
[*] Location: {loc_str}
[*] Function: {vulnerability['function']}
[*] Template: {vulnerability['template']}
[*] Top Expression: {vulnerability['top_expression']}
'''

            report_out(file_handle, report_readable)
            report_out(file_handle, f"{vulnerability_count}:{repr(vulnerability['tags'])} variable = {vulnerability['variable']}")
            report_out(file_handle, f"\t(loc:{loc_str}) {vulnerability['top_expression']}")

            for slice in vulnerability['slices']:
                loc = slice['location']
                loc_str = f"{loc['start_line']}:{loc['start_col']}"
                report_out(file_handle, f"\t(loc:{loc_str}) {slice['code']}")

            vulnerability_count += 1
    
    report_out(file_handle, '')

    if file_handle:
        file_handle.flush()
        file_handle.close()


def analyze_sink_type(tx, label, fn, args=()):

    vulnerabilities = []

    for expr_node, stmt_node, arg_node in fn(tx, *args):
        
        if do_reachability_analysis(tx, node=expr_node) == 'unreachable':
            label = 'NON-REACH'

        slices = get_varname_value_from_context(arg_node['Code'], expr_node)
        slices_format = [{'code': code, 'location': parse_location(location)} for code, _, _, location in slices]
        
        window_match = False if label != 'getElementById()' else True
        script_match = False if label == 'document.appendChild()' else True

        for code, args, ids, location in slices:

            window_match = True if window_match else CLOBBERING_REGEX.search(code)
            script_match = True if script_match else SCRIPT_REGEX.search(code)

            if window_match and script_match:

                vulnerabilities.append({
                    'tags': [label.upper()],
                    'node_id': {
                        'top_expression': expr_node['Id'],
                        'sink_expression': stmt_node['Id'],
                        'argument': arg_node['Id']
                    },
                    'function': label,
                    'template': None,
                    'location': parse_location(expr_node['Location']),
                    'top_expression': get_code_expression(getChildsOf(tx, expr_node))[0],
                    'variable': arg_node['Code'],
                    'slices': slices_format
                })

    return vulnerabilities


def run_analysis(report_out=None, report_json=True, debug=False):

    database = GraphDatabase.driver(constants.NEO4J_CONN_STRING, auth=(constants.NEO4J_USER, constants.NEO4J_PASS))
    with database.session() as session:
        with session.begin_transaction() as tx:

            vulnerabilities = []


            sink_types = [
                
                ('eval()', get_complex_call_sinks, (1, 'eval')),
                ('document.write()', get_complex_call_sinks, (1, 'write', 'document')),
                ('document.writeln()', get_complex_call_sinks, (1, 'writeln', 'document')),
                ('document.appendChild()', get_complex_call_sinks, (1, 'appendChild', 'document')),
                ('getElementById()', get_complex_call_sinks, (1, 'getElementById')),
                ('JSON.parse()', get_complex_call_sinks, (1, 'parse', 'JSON')),
                ('localStorage.setItem', get_complex_call_sinks, (2, 'setItem', 'localStorage')),
                ('sessionStorage.setItem', get_complex_call_sinks, (2, 'setItem', 'sessionStorage')),
                ('jQuery.parseHTML()', get_complex_call_sinks, (1, 'parseHTML', 'jQuery')),
                ('$()', get_complex_call_sinks, (1, '$')),
                ('jQuery()', get_complex_call_sinks, (1, 'jQuery')),

                ('document.cookie', get_property_assignment_sinks, ('cookie', 'document')),
                ('document.domain', get_property_assignment_sinks, ('domain', 'document')),
                ('window.location', get_property_assignment_sinks, ('location', 'window')),
                ('innerHTML', get_property_assignment_sinks, ('innerHTML',)),
                ('outerHTML', get_property_assignment_sinks, ('outerHTML',)),
                ('insertAdjacentHTML', get_property_assignment_sinks, ('insertAdjacentHTML',)),
                ('onevent', get_property_assignment_sinks, ('onevent',))

            ]

            jquery_sinks = [
                (2, 'add'), (1, 'append'), (1, 'after'),
                (2, 'animate'), (1, 'insertAfter'), (1, 'insertBefore'), 
                (1, 'before'), (1, 'html'), (1, 'prepend'), 
                (1, 'replaceAll'), (1, 'replaceWith'), (1, 'wrap'), 
                (1, 'wrapInner'), (1, 'wrapAll'), (1, 'has'),
                (1, 'index'), (1, 'parseHTML')
            ]

            for n_arg, jquery_sink in jquery_sinks:
                sink_types.append(('$().%s()' % jquery_sink, get_complex_call_sinks, (n_arg, jquery_sink, '$')))

            for params in sink_types:
                vulnerabilities += analyze_sink_type(tx, *params)

            generate_report(vulnerabilities, report_out, report_json)


# FIXME: CSV generation not working
def generate_graph(relative_path, full_path):
    program_path_name = os.path.join(full_path, 'js_program.js')
    node_args = [
        'node', '--max-old-space-size=32000', constants.ANALYZER_DRIVER_PATH, 
        '-js', program_path_name, '-o', relative_path
    ]
    print(' '.join(node_args))
    node_proc = subprocess.Popen(node_args, stdout=subprocess.PIPE)
    if constants.DEBUG_PRINTS:
        for line in node_proc.stdout:
            print(line.decode('UTF-8'))
    node_proc.wait()
    return node_proc.returncode


def import_site_data(site_id=0, site_url=None, use_url_id=False, generate_only=False, overwrite=False):

    url_hash = site_url if use_url_id else _hash(site_url)
    relative_path = os.path.join(str(site_id), url_hash)
    full_path = os.path.join(os.path.join(PROJECT_ROOT, f'hpg_construction{os.path.sep}outputs'), relative_path)
    
    node_path = os.path.join(full_path, constants.NODE_INPUT_FILE_NAME)
    rels_path = os.path.join(full_path, constants.RELS_INPUT_FILE_NAME)
    if not overwrite and os.path.exists(node_path) and os.path.exists(rels_path):
        print('Graph already exists, skipping...')
    else: generate_graph(relative_path, full_path)

    if not generate_only:
        API_neo4j_prepare(full_path)

    print('Done!')


if __name__ == '__main__':

    jaw_data_path = os.path.join(PROJECT_ROOT, f'..{os.path.sep}JAWData')

    main_parser = argparse.ArgumentParser(description='Large Scale Analysis of DOM Clobbering Vulnerabilities')
    sub_parsers = main_parser.add_subparsers(dest='action', required=True)

    import_parser = sub_parsers.add_parser('import')

    import_group = import_parser.add_mutually_exclusive_group(required=True)
    import_group.add_argument('--id',  metavar='id', type=int, help='ID of the website to import')

    import_parser.add_argument('--url', metavar='url', type=str, help='URL of the site to import')
    import_parser.add_argument('--url_id', action='store_true', help='Use the URL ID as is without re-hashing')

    import_ex_group = import_parser.add_mutually_exclusive_group()
    import_ex_group.add_argument('--generate_only', action='store_true', help='Only generate graph without importing')
    import_ex_group.add_argument('--overwrite', action='store_true', help='Overwrite graph if files already exist')

    analysis_parser = sub_parsers.add_parser('analyze')
    analysis_parser.add_argument('--out', metavar='filename', type=str, help='Path to output the analysis report to')
    analysis_parser.add_argument('--json', action='store_true', help='Output the report in JSON format.')

    args = main_parser.parse_args()

    if args.action == 'analyze':
        run_analysis(args.out, args.json)
    elif args.action == 'import':
        import_site_data(args.id, args.url, args.url_id, args.generate_only, args.overwrite)
    else:
        sys.exit(-1)