import constants

from neo4j import GraphDatabase
from hpg_analysis.general import data_flow

if __name__ == '__main__':
    database = GraphDatabase.driver(constants.NEO4J_CONN_STRING, auth=(constants.NEO4J_USER, constants.NEO4J_PASS))
    with database.session() as session:
        with session.begin_transaction() as transaction:
            results = transaction.run('''
                MATCH   (expr_stmt)-[:AST_parentOf {RelationType: "expression"}]->(call_expr {Type: "CallExpression"})-[:AST_parentOf {RelationType: "callee"}]->(callee),
                        (call_expr)-[:AST_parentOf {RelationType: "arguments"}]->(call_arg),
                        (callee)-[:AST_parentOf*2]->({Type: "Identifier", Code: "document"}),
                        (callee)-[:AST_parentOf]->({Type: "Identifier", Code: "appendChild"})
                RETURN  expr_stmt, call_arg;
            ''')
            for result in results:
                expr_stmt = result['expr_stmt']
                call_arg = result['call_arg']
                slices = data_flow._get_varname_value_from_context(transaction, call_arg['Code'], expr_stmt)
                for i in range(0, len(slices)):
                    current_slice = slices[i]
                    if 'window.' in current_slice[0]:
                        print('DOM clobbering source found in document.*.appendChild() sink: %s (%s)' % (current_slice[0],str(current_slice[3])))