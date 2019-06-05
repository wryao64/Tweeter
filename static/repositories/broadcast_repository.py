import sqlite3

import cherrypy

DB_STRING = 'messages.db'


def set_up_database():
    with sqlite3.connect(DB_STRING) as con:
        con.execute("""CREATE TABLE broadcasts (
            loginserver_record,
            message,
            sender_created_at,
            signature)""")

def get_broadcasts():
    pass

def post_broadcast():
    pass
