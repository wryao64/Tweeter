import cherrypy

import static.api.login_server as login_server

startHTML = """<html>
                <head>
                    <title>Python Project</title>
                    <link rel="stylesheet" href="/static/css/styles.css" />
                </head>
                
                <body>
                    <a href="list_online_users">list online users</a><br/>
                    <a href="server_pubkey">server pubkey</a><br/>
                    <a href="add_pubkey">add pubkey</a><br/>
                    <a href="check_pubkey">check pubkey</a><br/>
                    <a href="get_loginserver_record">get login server record</a><br/>
                    <a href="add_privatedata">add private data</a><br/>
                    <a href="get_privatedata">get private data</a><br/>
                    <a href="list_apis">list apis</a><br/>
                    <a href="load_new_apikey">load new apikey</a><br/>
            """


class MainApp(object):
    # CherryPy Configuration
    _cp_config = {
        'tools.encode.on': True,
        'tools.encode.encoding': 'utf-8',
        'tools.sessions.on': 'True',
    }

    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + 'Error 404: Page does not exist.'
        cherrypy.response.status = 404
        return Page

    # Pages
    @cherrypy.expose
    def index(self):
        Page = startHTML + 'Welcome! This is the base website!<br/>'

        try:
            Page += 'Hello ' + cherrypy.session['username'] + '!<br/>'
            Page += 'You have logged in! <a href="/sign_out">Sign out</a>'
        except KeyError:  # There is no username
            Page += 'Click here to <a href="login">login</a>.'
        return Page

    @cherrypy.expose
    def login(self, bad_attempt=0):
        Page = startHTML

        if bad_attempt != 0:
            Page += '<font color="red">Invalid username/password!</font>'

        Page += '<form action="/sign_in" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="password" name="password"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page

    # Logging in and out
    @cherrypy.expose
    def sign_in(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        isLoggedIn = login_server.login(username, password)

        if isLoggedIn == True:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            self.username = username
            self.password = password
            raise cherrypy.HTTPRedirect('/')

            # tell user they are online

        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def sign_out(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        if username is None or password is None:
            pass
        else:
            isLoggedOut = login_server.logout(username, password)

            if isLoggedOut == True:
                cherrypy.lib.sessions.expire()
            raise cherrypy.HTTPRedirect('/')

    # Unsorted
    @cherrypy.expose
    def list_online_users(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        users = login_server.list_online_users(username, password)

        for user in users:
            Page += f"""
            Incoming pub key: {user['incoming_pubkey']}<br/>
            Username: {user['username']}<br/>
            Connection Location: {user['connection_location']}<br/>
            Connection Address: {user['connection_address']}<br/>
            Status: {user['status']}<br/>
            Connection Updated At: {user['connection_updated_at']}<br/>
            <br/>
            """

        return Page

    @cherrypy.expose
    def server_pubkey(self):
        Page = startHTML

        Page += login_server.server_pubkey()

        return Page

    @cherrypy.expose
    def add_privatedata(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.add_privatedata(username, password)

        return Page

    @cherrypy.expose
    def add_pubkey(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.add_pubkey(username, password)

        Page += f"""
        Login Server Record: {data['loginserver_record']}<br/>           
        """

        return Page

    @cherrypy.expose
    def check_pubkey(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.check_pubkey(username, password)

        Page += f"""
        Login Server Record: {data['loginserver_record']}<br/>
        Username: {data['username']}<br/>
        Connection Address: {data['connection_address']}<br/>
        Connection Location: {data['connection_location']}<br/>
        Connection Updated At: {data['connection_updated_at']}<br/>            
        """

        return Page

    @cherrypy.expose
    def get_loginserver_record(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.get_loginserver_record(username, password)

        Page += f"""
        Login Server Record: {data['loginserver_record']}<br/>           
        """

        return Page

    @cherrypy.expose
    def get_privatedata(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.get_privatedata(username, password)

        Page += f"""
        Private Keys: {data['prikeys']}<br/>
        Blocked Public Keys: {data['blocked_pubkeys']}<br/>
        Blocked Usernames: {data['blocked_usernames']}<br/>
        Blocked Words: {data['blocked_words']}<br/>
        Blocked Message Signatures: {data['blocked_message_signatures']}<br/>
        Favourite Message Signatures: {data['favourite_message_signatures']}<br/>
        Friends' Usernames: {data['friends_usernames']}<br/>
        """

        return Page

    @cherrypy.expose
    def list_apis(self):
        Page = startHTML

        data = login_server.list_apis()

        for d in data:
            if d != '/rx_broadcast' and d != '/rx_privatemessage':
                Page += f"""
                <strong>API: {d}</strong><br/>
                Method: {data[d]['method']}<br/>
                Requires auth: {data[d]['requires_auth']}<br/>
                Purpose: {data[d]['purpose']}<br/>
                <br/>
                """
            else:
                Page += f"""
                <strong>API: {d}</strong><br/>
                Method: {data[d]['method']}<br/>
                Purpose: {data[d]['purpose']}<br/>
                <br/>
                """

        return Page

    @cherrypy.expose
    def load_new_apikey(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.load_new_apikey(username, password)

        Page += data['api_key']

        return Page