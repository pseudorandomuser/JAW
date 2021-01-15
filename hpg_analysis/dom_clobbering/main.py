import constants

from neo4j import GraphDatabase

from hpg_analysis.general.control_flow import do_reachability_analysis
from hpg_analysis.general.data_flow import _get_varname_value_from_context

def get_document_appendchild_sinks(transaction):
    query = '''
        MATCH   (expr_node {Type: "ExpressionStatement"})-[:AST_parentOf {RelationType: "expression"}]
                    ->(call_expr {Type: "CallExpression"})-[:AST_parentOf {RelationType: "callee"}]->(callee),
                (call_expr)-[:AST_parentOf {RelationType: "arguments"}]->(args_node),
                (callee)-[:AST_parentOf*2]->({Type: "Identifier", Code: "document"}),
                (callee)-[:AST_parentOf]->({Type: "Identifier", Code: "appendChild"})
        RETURN  expr_node, args_node;
    '''
    return [(result['expr_node'], result['args_node']) for result in transaction.run(query)]

if __name__ == '__main__':
    database = GraphDatabase.driver(constants.NEO4J_CONN_STRING, auth=(constants.NEO4J_USER, constants.NEO4J_PASS))
    with database.session() as session:
        with session.begin_transaction() as transaction:
            for expr_node, args_node in get_document_appendchild_sinks(transaction):
                if do_reachability_analysis(transaction, expr_node.id) == 'unreachable':
                    print('Sink node with ID=%d is unreachable.' % expr_node.id); continue
                for slice in _get_varname_value_from_context(transaction, args_node['Code'], expr_node):
                    if 'window.' in slice[0]:
                        print('DOM clobbering source found in document.*.appendChild() sink: %s (%s)' % (slice[0], str(slice[3])))