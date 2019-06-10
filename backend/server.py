import cherrypy
import time

import static.api.login_server as login_server
import static.api.client_outgoing_request as client_outgoing_request
import static.api.client_incoming_request as client_incoming_request
import static.repositories.broadcast_repository as broadcast_repository
import static.repositories.private_message_repository as private_message_repository
import static.repositories.group_message_repository as group_message_repository
import static.repositories.user_repository as user_repository


startHTML = """<html>
                <head>
                    <title>Python Project</title>
                    <link rel="stylesheet" href="/static/css/styles.css" />
                </head>

                <body>
                    <a href="/">Home</a><br/>
                    <a href="/private_messages">Private Messages</a><br/>
                    <a href="/group_messages">Group Messages</a><br/>

                    <h1>LS endpoints</h1>
                    <a href="list_users">list online users</a><br/>
                    <a href="server_pubkey">server pubkey</a><br/>
                    <a href="add_pubkey">add pubkey</a><br/>
                    <a href="check_pubkey">check pubkey</a><br/>
                    <a href="get_loginserver_record">get login server record</a><br/>
                    <a href="add_privatedata">add private data</a><br/>
                    <a href="get_privatedata">get private data</a><br/>
                    <a href="list_apis">list apis</a><br/>
                    <a href="load_new_apikey">load new apikey</a><br/>

                    <br/>

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

            Page += """
            <h3>Change Status</h3>
            <form action="/change_status" method="post" enctype="multipart/form-data">
            <input type="radio" name="status" value="online">Online<br/>
            <input type="radio" name="status" value="busy">Busy<br/>
            <input type="radio" name="status" value="away">Away<br/>
            <input type="radio" name="status" value="offline">Offline<br/>
            <input type="submit" value="Change"/></form>

            <h3>Broadcast Message</h3>
            <form action="/broadcast_message" method="post" enctype="multipart/form-data">
            Message: <input type="message" name="message"/><br/>
            <input type="submit" value="Send"/></form>

            <h3>Check Messages</h3>
            <a href="check_messages">Check</a>
            <h3>Ping Check</h3>
            <a href="ping_check">Check</a><br/>

            <h3>Broadcasts</h3>
            """

            broadcasts = broadcast_repository.get_broadcasts()

            if len(broadcasts) == 0:
                Page += 'There are no broadcasts'
            else:
                for broadcast in broadcasts:
                    Page += str(broadcast) + '<br/><br/>'

            
        except KeyError:  # There is no username
            Page += 'Click here to <a href="login">login</a>.'
        return Page
        # return open('static/frontend/index.html')

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

    @cherrypy.expose
    def private_messages(self):
        Page = startHTML

        Page += """
        <h3>Private Message</h3>
        <form action="/private_message" method="post" enctype="multipart/form-data">
            Username: <input type='text' name='target_username'/><br>
            Message: <input type="message" name="message"/><br>
        <input type="submit" value="Send"/></form>
        """

        private_messages = private_message_repository.get_messages()

        if len(private_messages) == 0:
            Page += 'There are no messages'
        else:
            for message in private_messages:
                Page += str(message) + '<br/><br/>'

        return Page

    @cherrypy.expose
    def group_messages(self):
        Page = startHTML

        Page += """
        <h3>Group Message</h3>
        <form action="/group_message" method="post" enctype="multipart/form-data">
            Message: <input type="message" name="message"/><br/>
        <input type="submit" value="Send"/></form>

        <h3>Group Invite</h3>
        <form action="/group_invite" method="post" enctype="multipart/form-data">
            Username: <input type="username" name="username"/><br/>
        <input type="submit" value="Send"/></form>
        """

        group_messages = group_message_repository.get_messages()

        Page += '<h3>Group Messages</h3>'
        if len(group_messages) == 0:
            Page += 'There are no messages'
        else:
            for message in group_messages:
                Page += str(message) + '<br/><br/>'
        
        return Page

    @cherrypy.expose
    def broadcast_message(self, message=None):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        response = client_outgoing_request.broadcast(
            username, password, message)

        if response == 'ok':
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def private_message(self, message=None, target_username=None):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        response = client_outgoing_request.private_message(
            username, password, target_username, message)

        if response['response'] == 'ok':
            raise cherrypy.HTTPRedirect('/private_messages')
        else:
            raise cherrypy.HTTPRedirect('/private_messages')

    @cherrypy.expose
    def group_message(self, message=None):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        response = client_outgoing_request.group_message(
            username, password, message)

        if response['response'] == 'ok':
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def group_invite(self, username=None):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        response = client_outgoing_request.group_invite(
            username, password, username)

        if response['response'] == 'ok':
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def check_messages(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        response = client_outgoing_request.check_messages(username, password)

        if response['response'] == 'ok':
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def ping_check(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        response = client_outgoing_request.ping_check(
            username, password, '127.0.0.1:1025')

        if response['response'] == 'ok':
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/')

    # Logging in and out
    @cherrypy.expose
    def sign_in(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        response = login_server.login(username, password)

        if response['response'] == 'ok':
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            user_repository.post_user(username, password)
            ts = time.time()
            user_repository.post_login_time(username, ts)

            # check for messages sent while offline
            raise cherrypy.HTTPRedirect('/check_messages')
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
            response = login_server.logout(username, password)

            if response['response'] == 'ok':
                cherrypy.lib.sessions.expire()
                user_repository.delete_table()
        raise cherrypy.HTTPRedirect('/')

    # Unsorted
    @cherrypy.expose
    def change_status(self, status='online'):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        response = login_server.report_user_status(username, password, status)

        if response['response'] == 'ok':
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def list_users(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.list_users(username, password)

        try:
            users = data['users']

            for user in users:
                Page += """
                Incoming pub key: {}<br/>
                Username: {}<br/>
                Connection Location: {}<br/>
                Connection Address: {}<br/>
                Status: {}<br/>
                Connection Updated At: {}<br/>
                <br/>
                """.format(user['incoming_pubkey'], user['username'], user['connection_location'], user['connection_address'], user['status'], user['connection_updated_at'])

                user_repository.post_user_info(
                    user['username'], user['incoming_pubkey'])
        except KeyError:
            Page += data['message']

        return Page

    @cherrypy.expose
    def server_pubkey(self):
        Page = startHTML

        Page += login_server.server_pubkey()['pubkey']

        return Page

    @cherrypy.expose
    def add_privatedata(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = {
            'prikeys': ['cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'],
            'blocked_pubkeys': [],
            'blocked_usernames': [],
            'blocked_words': [],
            'blocked_message_signatures': [],
            'favourite_message_signatures': [],
            'friends_usernames': [],
        }
        response = login_server.add_privatedata(username, password, data)

        try:
            Page += 'Server received at: {}'.format(
                response['server_received_at'])
        except KeyError:
            Page += 'Server received at: {}'.format(response['message'])

        return Page

    @cherrypy.expose
    def add_pubkey(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.add_pubkey(username, password)

        try:
            Page += 'Login Server Record: {}'.format(
                data['loginserver_record'])
        except KeyError:
            Page += 'Login Server Record: {}'.format(data['message'])

        return Page

    @cherrypy.expose
    def check_pubkey(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        pubkey = '127e8c1ec5dd75335d59591fcb6701f9b446bddc98764c984a7ec97540d1f1a8'
        data = login_server.check_pubkey(username, password, pubkey)

        try:
            Page += """
            Login Server Record: {}<br/>
            Username: {}<br/>
            Connection Address: {}<br/>
            Connection Location: {}<br/>
            Connection Updated At: {}<br/>            
            """.format(data['loginserver_record'], data['username'], data['connection_address'], data['connection_location'], data['connection_updated_at'])
        except KeyError:
            Page += data['message']

        return Page

    @cherrypy.expose
    def get_loginserver_record(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.get_loginserver_record(username, password)

        try:
            Page += 'Login Server Record: {}'.format(
                data['loginserver_record'])
        except KeyError:
            Page += 'Login Server Record: {}'.format(data['message'])

        return Page

    @cherrypy.expose
    def get_privatedata(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.get_privatedata(username, password)

        try:
            Page += """
            Private Keys: {}<br/>
            Blocked Public Keys: {}<br/>
            Blocked Usernames: {}<br/>
            Blocked Words: {}<br/>
            Blocked Message Signatures: {}<br/>
            Favourite Message Signatures: {}<br/>
            Friends' Usernames: {}<br/>
            """.format(data['prikeys'], data['blocked_pubkeys'], data['blocked_usernames'], data['blocked_words'], data['blocked_message_signatures'], data['favourite_message_signatures'], data['friends_usernames'])
        except KeyError:
            Page += data['message']

        return Page

    @cherrypy.expose
    def list_apis(self):
        Page = startHTML

        data = login_server.list_apis()

        for d in data:
            if d != '/rx_broadcast' and d != '/rx_privatemessage':
                Page += """
                <strong>API: {}</strong><br/>
                Method: {}<br/>
                Requires auth: {}<br/>
                Purpose: {}<br/>
                <br/>
                """.format(d, data[d]['method'], data[d]['requires_auth'], data[d]['purpose'])
            else:
                Page += """
                <strong>API: {}</strong><br/>
                Method: {}<br/>
                Purpose: {}<br/>
                <br/>
                """.format(d, data[d]['method'], data[d]['purpose'])

        return Page

    @cherrypy.expose
    def load_new_apikey(self):
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        Page = startHTML

        data = login_server.load_new_apikey(username, password)

        try:
            Page += """
            API Key: {}<br>
            Generated at: {}
            """.format(data['api_key'], data['api_key_generated_at'])
        except KeyError:
            Page += data['message']

        return Page


class ApiApp(object):
    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_broadcast(self):
        try:
            loginserver_record = cherrypy.request.json['loginserver_record']
            message = cherrypy.request.json['message']
            sender_created_at = cherrypy.request.json['sender_created_at']
            signature = cherrypy.request.json['signature']

            response = client_incoming_request.broadcast(
                loginserver_record, message, sender_created_at, signature)
        except KeyError:
            response = {
                'response': 'error',
                'message': 'KeyError: key named incorrectly'
            }

        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        try:
            loginserver_record = cherrypy.request.json['loginserver_record']
            target_pubkey = cherrypy.request.json['target_pubkey']
            target_username = cherrypy.request.json['target_username']
            encrypted_message = cherrypy.request.json['encrypted_message']
            sender_created_at = cherrypy.request.json['sender_created_at']
            signature = cherrypy.request.json['signature']

            response = client_incoming_request.private_message(
                loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature)
        except KeyError:
            response = {
                'response': 'error',
                'message': 'KeyError: key named incorrectly'
            }

        return response

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def checkmessages(self, since):
        response = client_incoming_request.check_messages(since)

        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self):
        my_time = cherrypy.request.json['my_time']
        # my_active_usernames = cherrypy.request.json['my_active_usernames']
        connection_address = cherrypy.request.json['connection_address']
        connection_location = cherrypy.request.json['connection_location']

        # response = client_incoming_request.ping_check(
        #     my_time, my_active_usernames, connection_address, connection_location)
        response = client_incoming_request.ping_check(
            my_time, connection_address, connection_location)

        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_groupmessage(self):
        loginserver_record = cherrypy.request.json['loginserver_record']
        groupkey_hash = cherrypy.request.json['groupkey_hash']
        group_message = cherrypy.request.json['group_message']
        sender_created_at = cherrypy.request.json['sender_created_at']
        signature = cherrypy.request.json['signature']

        response = client_incoming_request.group_message(
            loginserver_record, groupkey_hash, group_message, sender_created_at, signature)

        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_groupinvite(self):
        loginserver_record = cherrypy.request.json['loginserver_record']
        groupkey_hash = cherrypy.request.json['groupkey_hash']
        target_pubkey = cherrypy.request.json['target_pubkey']
        target_username = cherrypy.request.json['target_username']
        encrypted_groupkey = cherrypy.request.json['encrypted_groupkey']
        sender_created_at = cherrypy.request.json['sender_created_at']
        signature = cherrypy.request.json['signature']

        response = client_incoming_request.group_invite(
            loginserver_record, groupkey_hash, target_pubkey, target_username, encrypted_groupkey, sender_created_at, signature)

        return response
