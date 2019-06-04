#!/usr/bin/python3
"""
This program uses the CherryPy web server (from www.cherrypy.org).
"""

import os

import cherrypy

import server

# The address we listen for connections on
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 1234


def runMainApp():
    # set up the config
    conf = {
        '/': {
            'tools.staticdir.root': os.getcwd(),
            'tools.encode.on': True,
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on': True,
            'tools.sessions.timeout': 60 * 1,
        },

        # configuration for the static assets directory
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
        },
    }

    cherrypy.site = {
        'base_path': os.getcwd()
    }

    # Create an instance of MainApp and tell CherryPy to send all requests under / to it. (i.e. all of them)
    cherrypy.tree.mount(server.MainApp(), "/", conf)
    cherrypy.tree.mount(server.ApiApp(), "/api/", conf)

    # Tell CherryPy where to listen, and to turn autoreload on
    cherrypy.config.update({
        'server.socket_host': LISTEN_IP,
        'server.socket_port': LISTEN_PORT,
        'engine.autoreload.on': True,
    })

    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()


# Run the function to start everything
if __name__ == '__main__':
    runMainApp()
