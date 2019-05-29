import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

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

    # PAGES
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

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password)

        if error == 0:
            cherrypy.session['username'] = username
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


"""
END OF MAINAPP
"""


def authoriseUserLogin(username, password):
    username = "wyao332"
    password = "wryao64_106379276"

    print("Log on attempt from {0}:{1}\n".format(username, password)) # FOR TESTING PURPOSES

    url = "http://cs302.kiwi.land/api/report"

    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d' # FOR TESTING PURPOSES
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

    # Obtain the verify key for a given signing key
    pubkey = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    #create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "connection_address": "127.0.0.1:8000",
        "connection_location": "2",
        "incoming_pubkey": pubkey_hex_str,
    }

    json_bytes = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=json_bytes, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
        return 1
