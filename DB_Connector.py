import pymysql
import re


def connect_to_db(host, port, user, password, db_name, charset='utf8mb4', cursor_class=pymysql.cursors.DictCursor):
    connection = pymysql.connect(host=host, port=port, user=user, password=password, db=db_name,
                                 charset=charset, cursorclass=cursor_class)
    return connection
