import pyodbc
import sqlite3
import logging

#logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(message)s', level=logging.DEBUG)
#logger = logging.getLogger(__name__)
#logger = logging.getLogger("logger")
#logger.setLevel(logging.DEBUG)
#logger.setLevel(logging.INFO)

logger = logging.getLogger()

class MyDB(object):

    _db_connection = None
    _db_cur = None

    def __init__(self, dbname):
        #self._db_connection = pyodbc.connect('host', 'user', 'password', 'db')
        #self._db_connection = pyodbc.connect('DRIVER={SQL Server};SERVER=localhost\SQLExpress;DATABASE=blockchain')
        self._db_connection = sqlite3.connect('{}.sqlite'.format(dbname))
        self._db_cur = self._db_connection.cursor()

        self.inittable('BLOCKS')
        self.inittable('TRANSACTIONS')

    def query(self, query, params):
        self._db_cur.execute(query, params)
        row = self._db_cur.fetchall()
        return row

    def insert(self, table, fields, values):
        #insertstatement = "INSERT INTO {}({}) VALUES('{}')".format(table, fields, values)
        insertstatement = "INSERT INTO {}({}) VALUES({})".format(table, fields, values)
        #logger.debug(insertstatement)
        try:
            self._db_cur.execute(insertstatement)
            self._db_connection.commit()
        except:
            logger.debug("Insert failed: {}".format(insertstatement))
            pass

    def update(self, updatestatement):

        logger.debug(updatestatement)
        try:
            self._db_cur.execute(updatestatement)
            self._db_connection.commit()
        except:
            logger.debug("Update failed: {}".format(updatestatement))
            pass

    def inittable(self, tablename):
        query = 'SELECT name FROM sqlite_master WHERE type=\'table\' AND name=\'{}\''.format(tablename)
        #print(query)
        result = self.query(query, '')
        #print(result)
        if not result:
            #logger.info('{} not found'.format(tablename))
            self.createtable(tablename)

    def createtable(self, tablename):
        logger.info('Creating table \'{}\'.'.format(tablename))
        if tablename.upper() == 'BLOCKS':
            self._db_connection.execute('''CREATE TABLE IF NOT EXISTS BLOCKS
                (ID INTEGER PRIMARY KEY     NOT NULL,
                version        INT,
                hash_prev       CHAR(64),
                hash_merkle     CHAR(64),
                time           TEXT,
                difficulty     INT,
                nonce          INT,
                size           INT,
                tx_count        INT
                   );''')

        elif tablename.upper() == 'TRANSACTIONS':
            self._db_connection.execute('''CREATE TABLE IF NOT EXISTS TRANSACTIONS
                (ID INTEGER PRIMARY KEY     NOT NULL,
                txHash         CHAR(64)
                );''')

        return

    def __del__(self):
        self._db_connection.close()


if __name__ == '__main__':

    db = MyDB('blockchain')

    query = 'SELECT * FROM BLOCKS'
    result = db.query(query, '')
    print('Query results: {}'.format(result))

    db.insert('BLOCKS', 'version, hashPrev', "'6', '00033466345300324987'")
    db.insert('TRANSACTIONS', 'txHash', "'11332a480a08fb0a13ae50d1b73fae163219f10d9c409ce1b59a574f2ff97f75'")

    result = db.query(query, '')
    for res in result:
        print('Result: {}'.format(res))
