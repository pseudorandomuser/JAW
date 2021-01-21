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
from hpg_analysis.general.data_flow import _get_varname_value_from_context

def get_document_append_child_sinks(transaction):
    query = '''
        MATCH   (expr_node {Type: "ExpressionStatement"})
                    -[:AST_parentOf {RelationType: "expression"}]->(call_expr {Type: "CallExpression"})
                    -[:AST_parentOf {RelationType: "callee"}]->(callee),
                (call_expr)-[:AST_parentOf {RelationType: "arguments"}]->(args_node),
                (callee)-[:AST_parentOf*2]->({Type: "Identifier", Code: "document"}),
                (callee)-[:AST_parentOf]->({Type: "Identifier", Code: "appendChild"})
        RETURN  expr_node, args_node;
    '''
    for result in transaction.run(query):
        yield (result['expr_node'], result['args_node']['Code'])

def get_eval_sinks(transaction):
    query = '''
        MATCH   (expr_node {Type: "ExpressionStatement"})
                    -[:AST_parentOf {RelationType: "expression"}]->(call_expr {Type: "CallExpression"})
                    -[:AST_parentOf {RelationType: "callee"}]->(callee {Type: "Identifier", Code: "eval"}),
                (call_expr)-[:AST_parentOf {RelationType: "arguments"}]->(args_node)
        RETURN  expr_node, args_node;
        '''
    for result in transaction.run(query):
        yield (result['expr_node'], result['args_node']['Code'])

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


if __name__ == '__main__':

    database = GraphDatabase.driver(constants.NEO4J_CONN_STRING, auth=(constants.NEO4J_USER, constants.NEO4J_PASS))
    with database.session() as session:
        with session.begin_transaction() as transaction:

            vulnerabilities = []

            # Analysis of document.*.appendChild() sinks

            for expr_node, arg in get_document_append_child_sinks(transaction):
                if do_reachability_analysis(transaction, expr_node.id, input_is_top=False) == 'unreachable': 
                    continue
                
                src_code = None
                src_location = None
                script_created = False

                for code, args, ids, location in _get_varname_value_from_context(transaction, arg, expr_node):
                    match_create = re.search('document\.createElement\([\'|"]([A-Za-z]*)[\'|"]\)', code)
                    match_window = re.search('window\.(.*)', code)
                    if match_create is not None:
                        groups = match_create.groups()
                        script_created = groups[0] == 'script'
                    if match_window is not None:
                        src_code, src_location = code, location

                if script_created and src_code and src_location:
                    vulnerabilities.append(('document.appendChild()', src_code, src_location))

            for expr_node, arg in get_eval_sinks(transaction):
                #if do_reachability_analysis(transaction, expr_node, input_is_top=True) == 'unreachable': 
                #    print('unreachable')
                #    continue

                for code, args, ids, location in _get_varname_value_from_context(transaction, arg, expr_node):
                    match_window = re.search('window\.(.*)', code)
                    if match_window is not None:
                        vulnerabilities.append(('eval()', code, location))

            # Print report about analysis results
            print_report(vulnerabilities)