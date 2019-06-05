import sqlite3

DB_STRING = 'messages.db'


def set_up_database():
    with sqlite3.connect(DB_STRING) as c:
        c.execute("""CREATE TABLE BROADCASTS (
            loginserver_record,
            message,
            sender_created_at,
            signature)""")


def get_broadcasts():
    with sqlite3.connect(DB_STRING) as c:
        r = c.execute("""SELECT loginserver_record, message, sender_created_at, signature
        FROM BROADCASTS""")
        return r.fetchall()


def post_broadcast(loginserver_record, message, sender_created_at, signature):
    with sqlite3.connect(DB_STRING) as c:
        c.execute("""INSERT INTO BROADCASTS
        (loginserver_record, message, sender_created_at, signature)
        VALUES (?, ?, ?, ?)""", (loginserver_record, message, sender_created_at, signature))
