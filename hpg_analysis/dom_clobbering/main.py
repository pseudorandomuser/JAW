import constants

from neo4j import GraphDatabase
from hpg_analysis.general import data_flow

if __name__ == '__main__':
    database = GraphDatabase.driver(constants.NEO4J_CONN_STRING, auth=(constants.NEO4J_USER, constants.NEO4J_PASS))
    with database.session() as session:
        with session.begin_transaction() as transaction:
            results = transaction.run('''
                MATCH   (call_expr {Type: "CallExpression"})-[:AST_parentOf {RelationType: "callee"}]->(callee),
                        (call_expr)-[:AST_parentOf {RelationType: "arguments"}]->(call_arg),
                        (callee)-[:AST_parentOf*2]->({Type: "Identifier", Code: "document"}),
                        (callee)-[:AST_parentOf]->({Type: "Identifier", Code: "appendChild"})
                RETURN  call_expr, call_arg;
            ''')
            for result in results:
                call_expr = result['call_expr']
                call_arg = result['call_arg']
                slices = data_flow._get_varname_value_from_context(transaction, call_arg['Code'], call_expr)
                print(repr(slices))