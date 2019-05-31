import cherrypy

import static.api.login_server as login_server

startHTML = """<html>
                <head>
                    <title>Python Project</title>
                    <link rel='stylesheet' href='/static/css/styles.css' />
                </head>
                
                <body>"""


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
        Page = startHTML + "Error 404: Page does not exist."
        cherrypy.response.status = 404
        return Page

    # Pages
    @cherrypy.expose
    def index(self):
        Page = startHTML + "Welcome! This is the base website!<br/>"

        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "You have logged in! <a href='/signout'>Sign out</a>"
        except KeyError:  # There is no username
            Page += "Click here to <a href='login'>login</a>."
        return Page

    @cherrypy.expose
    def login(self, bad_attempt=0):
        Page = startHTML

        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"

        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="password" name="password"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page

    # Logging in and out
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        isLoggedIn = login_server.login(username, password)

        if isLoggedIn == True:
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            raise cherrypy.HTTPRedirect('/')

            # tell user they are online

        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
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
