import sqlite3

DB_STRING = 'messages.db'


def set_up_database():
    with sqlite3.connect(DB_STRING) as c:
        r = c.execute("""SELECT COUNT(name)
        FROM sqlite_master
        WHERE type='table' AND name='GROUP_MESSAGES'
        """)

        if r.fetchone()[0] == 0:
            c.execute("""CREATE TABLE GROUP_MESSAGES (
                loginserver_record,
                groupkey_hash,
                group_message,
                sender_created_at,
                signature)""")


def get_messages():
    set_up_database()

    with sqlite3.connect(DB_STRING) as c:
        r = c.execute("""SELECT loginserver_record, groupkey_hash, group_message, sender_created_at, signature
        FROM GROUP_MESSAGES""")
        return r.fetchall()


def post_message(loginserver_record, groupkey_hash, group_message, sender_created_at, signature):
    set_up_database()

    with sqlite3.connect(DB_STRING) as c:
        c.execute("""INSERT INTO GROUP_MESSAGES
        (loginserver_record, groupkey_hash, group_message, sender_created_at, signature)
        VALUES (?, ?, ?, ?, ?)""", (loginserver_record, groupkey_hash, group_message, sender_created_at, signature))
