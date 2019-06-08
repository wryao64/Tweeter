#!/usr/bin/python3
"""
This program uses the CherryPy web server (from www.cherrypy.org).
"""

import os
# import logging

import cherrypy

import server

# The address we listen for connections on
LISTEN_IP = "127.0.0.1"  # local
# LISTEN_IP = '172.23.159.9'  # uni
LISTEN_PORT = 1025


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

    # Create an instance of server Apps and tell CherryPy to send all requests to relevant endpoints
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
