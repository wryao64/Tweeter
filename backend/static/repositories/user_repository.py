import sqlite3

DB_STRING = 'users.db'


def set_up_database():
    with sqlite3.connect(DB_STRING) as c:
        r = c.execute("""SELECT COUNT(name)
        FROM sqlite_master
        WHERE type='table' AND name='USER'
        """)

        if r.fetchone()[0] == 0:
            c.execute("""CREATE TABLE USER (
                username,
                password)""")

        r = c.execute("""SELECT COUNT(name)
        FROM sqlite_master
        WHERE type='table' AND name='LOGIN_RECORD'
        """)

        if r.fetchone()[0] == 0:
            c.execute("""CREATE TABLE LOGIN_RECORD (
                username,
                login_time)""")


def delete_table():
    with sqlite3.connect(DB_STRING) as c:
        c.execute('DROP TABLE USER')


def get_login_times(username):
    set_up_database()

    with sqlite3.connect(DB_STRING) as c:
        r = c.execute("""SELECT login_time
        FROM LOGIN_RECORD
        WHERE username = ?""", (username,))
        return r.fetchall()


def get_user():
    set_up_database()

    with sqlite3.connect(DB_STRING) as c:
        r = c.execute("""SELECT username, password
        FROM USER""")
        return r.fetchone()


def post_login_time(username, time):
    set_up_database()

    with sqlite3.connect(DB_STRING) as c:
        c.execute("""INSERT INTO LOGIN_RECORD
        (username, login_time)
        VALUES (?, ?)""", (username, time))


def post_user(username, password):
    set_up_database()

    with sqlite3.connect(DB_STRING) as c:
        c.execute("""INSERT INTO USER
        (username, password)
        VALUES (?, ?)""", (username, password))
