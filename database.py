import pyodbc
import logging

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(message)s', level=logging.DEBUG)
logger = logging.getLogger(__name__)
#logger = logging.getLogger("logger")
logger.setLevel(logging.DEBUG)
#logger.setLevel(logging.INFO)

class MyDB(object):

    _db_connection = None
    _db_cur = None

    def __init__(self):
        #self._db_connection = pyodbc.connect('host', 'user', 'password', 'db')
        self._db_connection = pyodbc.connect('DRIVER={SQL Server};SERVER=localhost\SQLExpress;DATABASE=blockchain')
        self._db_cur = self._db_connection.cursor()

    def query(self, query, params):
        self._db_cur.execute(query) #, params)
        row = self._db_cur.fetchall()
        return row

    def insert(self, table, fields, values):
        insertstatement = "insert into {}({}) values('{}')".format(table, fields, values)
        logger.debug(insertstatement)
        self._db_cur.execute(insertstatement)
        self._db_connection.commit()

    def __del__(self):
        self._db_connection.close()


if __name__ == '__main__':

    db = MyDB()


    result = db.query('select * from blocks', '')
    print(result)

    db.insert('blocks', 'version, hashPrev', "'6', '00033466345300324987'")

    result = db.query('select * from blocks', '')
    for res in result:
        print(res)
