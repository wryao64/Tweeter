import sqlite3

DB_STRING = 'messages.db'


def set_up_database():
    with sqlite3.connect(DB_STRING) as c:
        r = c.execute("""SELECT COUNT(name)
        FROM sqlite_master
        WHERE type='table' AND name='PRIVATE_MESSAGES'
        """)

        if r.fetchone()[0] == 0:
            c.execute("""CREATE TABLE PRIVATE_MESSAGES (
                loginserver_record,
                target_pubkey,
                target_username,
                encrypted_message,
                sender_created_at,
                signature)""")


def get_messages(since=None):
    set_up_database()

    with sqlite3.connect(DB_STRING) as c:
        if since == None:
            r = c.execute("""SELECT loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature
            FROM PRIVATE_MESSAGES""")
            return r.fetchall()
        else:
            r = c.execute("""SELECT loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature
            FROM PRIVATE_MESSAGES
            WHERE sender_created_at > ?""", (since,))
            return r.fetchall()


def post_message(loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature):
    set_up_database()

    with sqlite3.connect(DB_STRING) as c:
        c.execute("""INSERT INTO PRIVATE_MESSAGES
        (loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature)
        VALUES (?, ?, ?, ?, ?, ?)""", (loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature))
