# Import standard Python libraries

import re
import os
import sys
import json
import time
import logging
import argparse
import subprocess
import multiprocessing

from neo4j import GraphDatabase

# Import project modules

import constants

from utils.utility import _hash

from hpg_analysis.general.control_flow import do_reachability_analysis
from hpg_analysis.general.data_flow import get_varname_value_from_context

from hpg_neo4j.db_utility import API_neo4j_prepare
from hpg_neo4j.query_utility import getChildsOf, get_code_expression

from hpg_analysis.dom_clobbering.const import WINDOW_PREDEFINED_PROPERTIES

# Setup logging (Enable Neo4j logging level=logging.DEBUG)

logging.basicConfig(format='%(asctime)s (%(name)s) [%(levelname)s] %(funcName)s(): %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
LOGGER = logging.getLogger('dom-clobbering')
LOGGER.setLevel(logging.DEBUG)

# Other constants

MAX_TIME_SLICING_MINS = 15

SCRIPT_REGEX = re.compile('document\.createElement\([\'|"](script)[\'|"]\)')


def run_query(tx, query):
    LOGGER.debug(query)
    r = tx.run(query)
    LOGGER.debug('Query OK')
    return r


def get_property_assignment_sinks(tx, property, obj=None):

    obj_slice = ''
    if obj is not None:
        obj_slice = ',\n(left_expr)-[:AST_parentOf*1..5 {RelationType: "object"}]->(object_node {Type: "Identifier", Code: "%s"})' % obj

    query = '''MATCH (expr_node {Type: "ExpressionStatement"})-[:AST_parentOf {RelationType: "expression"}]->(assign_expr {Type: "AssignmentExpression"}),
                (assign_expr)-[:AST_parentOf {RelationType: "right"}]->(right_expr),
                (assign_expr)-[:AST_parentOf {RelationType: "left"}]->(left_expr {Type: "MemberExpression"}),
                (left_expr)-[:AST_parentOf {RelationType: "property"}]->(property_node {Type: "Identifier", Code: "%s"})%s
        RETURN expr_node, assign_expr, right_expr;''' % (property, obj_slice)

    '''
        WHERE right_expr.Type = 'Identifier' OR right_expr.Type = 'MemberExpression'''

    for r in run_query(tx, query):
        for arg_id_node in get_id_nodes(tx, r['right_expr']):
            yield (r['expr_node'], r['assign_expr'], r['right_expr'], arg_id_node)


def get_complex_call_sinks(tx, n_args, func, obj=None):

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

    for result in run_query(tx, query):
        expr_node = result['expr_node']
        call_expr = result['call_expr']
        for i in range(0, n_args):
            arg_node = result['arg_node_%d' % i]
            for arg_id_node in get_id_nodes(tx, arg_node):
                yield (expr_node, call_expr, arg_node, arg_id_node)


def get_id_nodes(tx, node):

    if node['Type'] == 'Identifier':
        yield node
    query = '''MATCH ({Id: "%s"})-[rels:AST_parentOf*1..10]->(id_node {Type: "Identifier"})
        WHERE ALL (rel IN rels WHERE 
            rel.RelationType = "object" OR 
            rel.RelationType = "left" OR 
            rel.RelationType = "right"
        )
        RETURN id_node;
    ''' % node['Id']

    for result in run_query(tx, query):
        yield result['id_node']


def get_vulnerable_source(tx, id):
    
    query = '''MATCH (decl_node {Type: "VariableDeclarator"})
                -[:AST_parentOf {RelationType: "id"}]->(id_node {Type: "Identifier"}), 
            (decl_node)-[:AST_parentOf*1..10]->(member_node {Type: "MemberExpression"})
                -[:AST_parentOf*1..10 {RelationType: "object"}]->(wnd_node {Id: "%s"}),
            (member_node)-[:AST_parentOf {RelationType: "property"}]->(prop_node) 
            RETURN decl_node, id_node, member_node, prop_node;
    ''' % id

    for result in run_query(tx, query):
        return result

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


def node_str(tx, node):
    return get_code_expression(getChildsOf(tx, node))[0]


def write_all(file, text):
    if file:
        file.write(text)
        file.flush()
    sys.stdout.write(text)
    sys.stdout.flush()


def generate_report(vulnerabilities, out_path, make_json):

    if make_json and out_path:
        simple_path = os.path.splitext(out_path)[0]
        with open(f'{simple_path}.json', 'w') as json_report:
            write_all(json_report, json.dumps(vulnerabilities, indent = 4))

    print('\n')

    report = open(out_path, 'w') if out_path else None

    vulnerability_count = 1
    for vulnerability in vulnerabilities:

        loc = vulnerability['location']
        loc_str = f"{loc['start_line']}:{loc['start_col']}"
            
        # tag is actually source
        report_readable = f'''[*] Source type: {vulnerability['source_type']}
[*] Sink type: {vulnerability['sink_type']}
[*] Node Id: {repr(vulnerability['node_id'])}
[*] Location: {loc_str}
[*] Template: {vulnerability['template']}
[*] Top Expression: {vulnerability['top_expression']}\n\n'''

        write_all(report, report_readable)
        write_all(report, f"{vulnerability_count}:{repr(vulnerability['tags'])} variable = {vulnerability['variable']}\n")
        write_all(report, f"\t(loc:{loc_str}) {vulnerability['top_expression']}\n")

        for slice in vulnerability['slices']:
            loc = slice['location']
            loc_str = f"{loc['start_line']}:{loc['start_col']}"
            write_all(report, f"\t(loc:{loc_str}) {slice['code']}\n")

        vulnerability_count += 1
    
        if vulnerability_count < len(vulnerabilities) + 1:
            write_all(report, '\n')

    if report:
        report.close()


def slicing_routine(pipe, arg_node, expr_node):
    LOGGER.debug(f'Spawned slicing process with PID {os.getpid()}')
    slices = get_varname_value_from_context(arg_node, expr_node)
    pipe.send(slices)
    pipe.close()


def do_multiproc_slicing(arg_id_node, expr_node):
    LOGGER.debug(f'Spawning slicing process from PID {os.getpid()}...')

    parent_pipe, child_pipe = multiprocessing.Pipe()
    slicing_proc = multiprocessing.Process(target=slicing_routine, args=(child_pipe, arg_id_node['Code'], expr_node))
    slicing_proc.start()

    slicing_result_present = False

    try:
        for i in range(0, MAX_TIME_SLICING_MINS):
            slicing_result_present = parent_pipe.poll(timeout=60.0)
            if slicing_result_present:
                LOGGER.debug('Slicing process has data!')
                break
            remaining_mins = MAX_TIME_SLICING_MINS - i
            LOGGER.debug(f'Killing slicing process in {remaining_mins} minutes...')
    except KeyboardInterrupt:
        LOGGER.debug('User aborted current slicing process...')

    if not slicing_result_present:
        LOGGER.debug('Slicing did not terminate within the specified timespan, continuing...')
        slicing_proc.terminate()
        slicing_proc.join(timeout=10)
        child_pipe.close()
        parent_pipe.close()
        return None

    try:
        slices = parent_pipe.recv()
        parent_pipe.close()
        slicing_proc.join()
        return slices
    except:
        LOGGER.debug('Could not read slices from child process, continuing...')
        parent_pipe.close()
        return None


def analyze_sink_type(tx, label, fn, args=()):

    vulnerabilities = []

    for expr_node, stmt_node, arg_top_node, arg_id_node in fn(tx, *args):

        LOGGER.debug('\n%s' * 4, repr(expr_node), repr(stmt_node), repr(arg_top_node), repr(arg_id_node))

        LOGGER.debug('Begin reachability analysis...')
        if do_reachability_analysis(tx, node=expr_node) == 'unreachable':
            label = 'NON-REACH'
            LOGGER.debug('Current node is unreachable!')

        slices = do_multiproc_slicing(arg_id_node, expr_node)
        if not slices:
            LOGGER.debug('No slices, continuing...')
            continue

        LOGGER.debug(slices)

        slices_format = [{
            'code': code, 
            'location': parse_location(location)
        } for code, _, _, location in slices]

        source = None
        script_match = False if label == 'document.appendChild()' else True

        for code, args, ids, location in slices:

            if not source and 'window' in ids:
                LOGGER.debug('Window is in slices, looking for vulnerable source...')
                result = get_vulnerable_source(tx, ids['window'])
                LOGGER.debug(result)
                if result and result['prop_node']['Code'] not in WINDOW_PREDEFINED_PROPERTIES:
                    source = result

            script_match = script_match if script_match else SCRIPT_REGEX.search(code)

            if source and script_match:

                vulnerabilities.append({
                    'tags': [label.upper()],
                    'sink_type': label,
                    'source_type': node_str(tx, source['member_node']),
                    'node_id': {
                        'top_expression': expr_node['Id'],
                        'sink_expression': stmt_node['Id'],
                        'argument': arg_top_node['Id']
                    },
                    'template': node_str(tx, arg_top_node),
                    'location': parse_location(expr_node['Location']),
                    'top_expression': node_str(tx, expr_node),
                    'variable': source['id_node']['Code'],
                    'slices': slices_format
                })

                break

    return vulnerabilities


def run_analysis(out_path, make_json):

    LOGGER.debug('Establishing database connection...')
    database = GraphDatabase.driver(
        constants.NEO4J_CONN_STRING, 
        auth=(
            constants.NEO4J_USER, 
            constants.NEO4J_PASS
        )
    )

    with database.session() as session:
        with session.begin_transaction() as tx:

            vulnerabilities = []

            sink_types = [
                ('eval()', get_complex_call_sinks, (1, 'eval')),
                ('document.write()', get_complex_call_sinks, (1, 'write', 'document')),
                ('document.writeln()', get_complex_call_sinks, (1, 'writeln', 'document')),
                ('document.appendChild()', get_complex_call_sinks, (1, 'appendChild', 'document')),
                #('getElementById()', get_complex_call_sinks, (1, 'getElementById')),
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

            LOGGER.debug('Analysis finished, generating report...')
                
            generate_report(vulnerabilities, out_path, make_json)

    database.close()


def generate_graph(relative_path, full_path):
    program_path_name = os.path.join(full_path, 'js_program.js')

    LOGGER.debug('Parser returned %s' % str(parse_js(program_path_name)))

    node_args = [
        'node', '--max-old-space-size=32000', constants.ANALYZER_DRIVER_PATH, 
        '-js', program_path_name, '-o', relative_path
    ]
    LOGGER.debug(' '.join(node_args))
    node_proc = subprocess.Popen(node_args, stdout=subprocess.PIPE)
    if constants.DEBUG_PRINTS:
        for line in node_proc.stdout:
            print(line.decode('UTF-8'))
    node_proc.wait()
    return node_proc.returncode


def parse_js(path):
    proc = subprocess.Popen([
        'node', os.path.join(constants.CLOBBER_ROOT, 'parse.js'), path
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()
    return proc.returncode == 0


def import_site_data(site_id=0, url_id=None, url=None, generate_only=False, overwrite=False):

    url_hash = url_id if url_id else _hash(url)
    relative_path = os.path.join(str(site_id), url_hash)
    full_path = os.path.join(os.path.join(constants.BASE_DIR, f'hpg_construction{os.path.sep}outputs'), relative_path)
    
    node_path = os.path.join(full_path, constants.NODE_INPUT_FILE_NAME)
    rels_path = os.path.join(full_path, constants.RELS_INPUT_FILE_NAME)
    if not overwrite and os.path.exists(node_path) and os.path.exists(rels_path):
        LOGGER.info('Graph already exists, skipping...')
    else:
        graph_ret = generate_graph(relative_path, full_path)
        LOGGER.debug('Graph generation returned %d' % graph_ret)

    if not generate_only:
        API_neo4j_prepare(full_path)

    LOGGER.info('Done!')


if __name__ == '__main__':

    jaw_data_path = os.path.join(constants.BASE_DIR, f'..{os.path.sep}JAWData')

    main_parser = argparse.ArgumentParser(description='Large Scale Analysis of DOM Clobbering Vulnerabilities')
    sub_parsers = main_parser.add_subparsers(dest='action', required=True)

    import_parser = sub_parsers.add_parser('import')

    import_parser.add_argument('--id',  metavar='id', type=int, help='ID of the website to import')

    import_id_group = import_parser.add_mutually_exclusive_group(required=True)
    import_id_group.add_argument('--url_id', metavar='id', type=str, help='URL ID of the site')
    import_id_group.add_argument('--url', metavar='url', type=str, help='URL of the site to import')

    import_parser.add_argument('--generate_only', action='store_true', help='Only generate graph without importing')
    import_parser.add_argument('--overwrite', action='store_true', help='Overwrite graph if files already exist')

    analysis_parser = sub_parsers.add_parser('analyze')
    analysis_parser.add_argument('--out', metavar='filename', type=str, help='Path to output the analysis report to')
    analysis_parser.add_argument('--json', action='store_true', help='Also generate the report in JSON format.')

    args = main_parser.parse_args()

    if args.action == 'analyze':
        run_analysis(args.out, args.json)
    elif args.action == 'import':
        import_site_data(args.id, args.url_id, args.url, args.generate_only, args.overwrite)
    else:
        sys.exit(-1)