import re
import os
import sys
import ast

from neo4j import GraphDatabase

#Add JAW root to path for imports
sys.path.append(os.path.join(
    os.path.dirname(sys.argv[0]), f'..{os.path.sep}..'
))

import constants
from hpg_analysis.general.control_flow import do_reachability_analysis
from hpg_analysis.general.data_flow import get_varname_value_from_context




def get_document_append_child_sinks(tx):
    query = '''MATCH   (expr_node {Type: "ExpressionStatement"})
                    -[:AST_parentOf {RelationType: "expression"}]->(call_expr {Type: "CallExpression"})
                    -[:AST_parentOf {RelationType: "callee"}]->(callee),
                (call_expr)-[:AST_parentOf {RelationType: "arguments"}]->(args_node),
                (callee)-[:AST_parentOf*2]->({Type: "Identifier", Code: "document"}),
                (callee)-[:AST_parentOf]->({Type: "Identifier", Code: "appendChild"})
        RETURN  expr_node, args_node;'''
    return [(r['expr_node'], r['args_node']['Code']) for r in tx.run(query)]

def get_obj_property_sinks(tx, obj, property):
    query = '''MATCH    (expr_node {Type: "ExpressionStatement"})
                    -[:AST_parentOf {RelationType: "expression"}]->(assign_expr {Type: "AssignmentExpression"}),
                (assign_expr)-[:AST_parentOf {RelationType: "right"}]->(right_expr {Type: "Identifier"}),
                (assign_expr)-[:AST_parentOf {RelationType: "left"}]->(left_expr {Type: "MemberExpression"}),
                (left_expr)-[:AST_parentOf {RelationType: "object"}]->(doc_node {Type: "Identifier", Code: "%s"}),
                (left_expr)-[:AST_parentOf {RelationType: "property"}]->(property_node {Type: "Identifier", Code: "%s"})
        RETURN expr_node, right_expr;''' % (obj, property)
    return [(r['expr_node'], r['right_expr']['Code']) for r in tx.run(query)]

def get_property_sinks(tx, property):
    query = '''MATCH    (expr_node {Type: "ExpressionStatement"})
                    -[:AST_parentOf {RelationType: "expression"}]->(assign_expr {Type: "AssignmentExpression"}),
                (assign_expr)-[:AST_parentOf {RelationType: "right"}]->(right_expr {Type: "Identifier"}),
                (assign_expr)-[:AST_parentOf {RelationType: "left"}]->(left_expr {Type: "MemberExpression"}),
                (left_expr)-[:AST_parentOf {RelationType: "property"}]->(property_node {Type: "Identifier", Code: "%s"})
        RETURN expr_node, right_expr;''' % property
    return [(r['expr_node'], r['right_expr']['Code']) for r in tx.run(query)]

def get_eval_sinks(tx):
    query = '''MATCH   (expr_node {Type: "ExpressionStatement"})
                    -[:AST_parentOf {RelationType: "expression"}]->(call_expr {Type: "CallExpression"})
                    -[:AST_parentOf {RelationType: "callee"}]->(callee {Type: "Identifier", Code: "eval"}),
                (call_expr)-[:AST_parentOf {RelationType: "arguments"}]->(args_node)
        RETURN  expr_node, args_node;'''
    return [(r['expr_node'], r['args_node']['Code']) for r in tx.run(query)]

def get_json_sinks(tx):
    query = '''MATCH   (decl_node {Type: "VariableDeclaration"})
                    -[:AST_parentOf*2]->(call_expr {Type: "CallExpression"}),
                (call_expr)-[:AST_parentOf {RelationType: "arguments"}]->(args_node {Type: "Identifier"}),
                (call_expr)-[:AST_parentOf {RelationType: "callee"}]->(callee_node {Type: "MemberExpression"}),
                (callee_node)-[:AST_parentOf {RelationType: "property"}]->({Type: "Identifier", Code: "parse"}),
                (callee_node)-[:AST_parentOf {RelationType: "object"}]->({Type: "Identifier", Code: "JSON"})
        RETURN decl_node, args_node;
                '''
    return [(r['decl_node'], r['args_node']['Code']) for r in tx.run(query)]




def print_report(vulnerabilities):

    report_header = '''
###################################
# DOM Clobbering Analysis Results #
###################################'''

    vulnerability_str = ''
    for sink, code, location in vulnerabilities:
        location_regex = re.match('{start:{line:([0-9]+),column:([0-9]+)},end:{line:([0-9]+),column:([0-9]+)}}', location)
        start_line, start_col, end_line, end_col = location_regex.groups()
        vulnerability_str += f'\nLocation:\tLine {start_line} column {start_col}\nSink type:\t{sink}\nSource code:\t{code}\n'

    vulnerabilities_len = len(vulnerabilities)
    assessment_str = f'Final assessment: {vulnerabilities_len} ' \
        + f'Vulnerabilit{"ies were" if vulnerabilities_len > 1 else "y was"} found.\n' \
        + f'{"A" if vulnerabilities_len > 0 else "No a"}ction needs to be taken.'

    print(f'{report_header}\n{vulnerability_str}\n{assessment_str}\n')




def do_generic_analysis(tx, label, fn, args=()):
    vulnerabilities = []
    for expr_node, slice_criterion in fn(tx, *args):
        #if do_reachability_analysis(tx, node_id=expr_node.id) == 'unreachable':
        #    continue
        for code, args, ids, location in get_varname_value_from_context(slice_criterion, expr_node):
            match_window = re.search('window\.(.*)', code)
            if match_window is not None:
                vulnerabilities.append((label, code, location))
    return vulnerabilities




if __name__ == '__main__':

    database = GraphDatabase.driver(constants.NEO4J_CONN_STRING, auth=(constants.NEO4J_USER, constants.NEO4J_PASS))
    with database.session() as session:
        with session.begin_transaction() as tx:


            vulnerabilities = []




            generic_queries = [
                ('eval()', get_eval_sinks),
                ('document.cookie', get_obj_property_sinks, ('document', 'cookie')),
                ('document.domain', get_obj_property_sinks, ('document', 'domain')),
                ('window.location', get_obj_property_sinks, ('window', 'location')),
                ('innerHTML', get_property_sinks, ('innerHTML',)),
                ('JSON.parse', get_json_sinks)
            ]

            for params in generic_queries:
                vulnerabilities += do_generic_analysis(tx, *params)




            # Analysis of document.*.appendChild() sinks (!)
            
            for expr_node, arg in get_document_append_child_sinks(tx):

                if do_reachability_analysis(tx, node_id=expr_node.id) == 'unreachable': 
                    continue

                src_code = None
                src_location = None
                script_created = False

                for code, args, ids, location in get_varname_value_from_context(arg, expr_node):
                    match_create = re.search('document\.createElement\([\'|"]([A-Za-z]*)[\'|"]\)', code)
                    match_window = re.search('window\.(.*)', code)
                    if match_create is not None:
                        groups = match_create.groups()
                        script_created = groups[0] == 'script'
                    if match_window is not None:
                        src_code, src_location = code, location

                if script_created and src_code and src_location:
                    vulnerabilities.append(('document.appendChild()', src_code, src_location))


            # Print report about analysis results
            print_report(vulnerabilities)