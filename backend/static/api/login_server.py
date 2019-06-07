import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

import static.utils.api_helper as api_helper
import static.utils.security_helper as security_helper


def add_privatedata(username, password):
    """
    Saves symmetrically encrypted private data for a user
    """
    url = 'http://cs302.kiwi.land/api/add_privatedata'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
    key = 'strongkey'  # FOR TESTING PURPOSE: change to take user input

    data = {
        'prikeys': ['cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'],
        'blocked_pubkeys': [],
        'blocked_usernames': [],
        'blocked_words': [],
        'blocked_message_signatures': [],
        'favourite_message_signatures': [],
        'friends_usernames': [],
    }

    json_data = json.dumps(data)

    encrypted_data = security_helper.encrypt_data(key, json_data)

    loginserver_record = get_loginserver_record(
        username, password)['loginserver_record']
    ts = time.time()

    keys = security_helper.get_keys(
        encrypted_data + loginserver_record + str(ts))  # FOR TESTING PURPOSES

    headers = api_helper.create_header(username, password)

    payload = {
        'privatedata': encrypted_data,
        'loginserver_record': loginserver_record,
        'client_saved_at': str(ts),
        'signature': keys['signature'],
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)

    return data_object


def add_pubkey(username, password):
    """
    Associates a public key with the user's account

    Return:
    data_object - 
    """
    url = "http://cs302.kiwi.land/api/add_pubkey"

    keys = security_helper.get_public_key

    headers = api_helper.create_header(username, password)

    payload = {
        "pubkey": keys['pubkey'],
        "username": username,
        "signature": keys['signature'],
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)

    # response = ok, return keys

    return data_object


def check_pubkey(username, password):
    """
    Loads the loginserver_record for a given public key
    """
    url = "http://cs302.kiwi.land/api/check_pubkey"

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
    keys = security_helper.get_keys()  # FOR TESTING PURPOSES

    headers = api_helper.create_header(username, password)

    url += "?pubkey=" + keys['pubkey']

    data_object = api_helper.get_data(url, headers=headers)
    return data_object


def get_loginserver_record(username, password):
    """
    Loads the user's current loginserver_record for use in creating point-to-point messages.
    """
    url = 'http://cs302.kiwi.land/api/get_loginserver_record'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    headers = api_helper.create_header(username, password)

    data_object = api_helper.get_data(url, headers=headers)
    return data_object


def get_privatedata(username, password):
    """
    Loads the saved symmetrically encrypted private data of the user

    Return:
    privatedata - decrypted data as Python object
    """
    url = 'http://cs302.kiwi.land/api/get_privatedata'

    key = 'strongkey'  # FOR TESTING PURPOSE: change to take user input

    headers = api_helper.create_header(username, password)

    data_object = api_helper.get_data(url, headers=headers)

    encrypted_data = data_object['privatedata']
    decrypted_data = security_helper.decrypt_data(key, encrypted_data)
    privatedata = json.loads(decrypted_data)

    return privatedata


def list_online_users(username, password):
    """
    Lists the connection details for all active users within the last five minutes
    """
    url = 'http://cs302.kiwi.land/api/list_users'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    headers = api_helper.create_header(username, password)

    data_object = api_helper.get_data(url, headers=headers)
    users = data_object['users']
    return users


def login(username, password):
    """
    User sign in
    """
    isAuthenticated = ping(username, password)

    if isAuthenticated == 'ok':
        # check public/private keypair

        # test pub/priv keypair

        response = report_user_status(username, password, 'online')
        if response == 'ok':
            return True
        else:
            return False
    else:
        return False


def logout(username, password):
    """
    User sign out
    """
    response = report_user_status(username, password, 'offline')
    if response == 'ok':
        return True
    else:
        return False


def ping(username, password):
    """
    Checks if the login server is online and authenticates login

    Return:
    string - 'ok' if authenticated, an error message if there is an error
    """
    url = 'http://cs302.kiwi.land/api/ping'

    prikey = get_privatedata(username, password)['prikeys'][0]  # assuming there is always a private key
    pubkey = security_helper.get_public_key(prikey)
    signature = security_helper.get_signature(prikey, pubkey)

    headers = api_helper.create_header(username, password)

    payload = {
        "pubkey": pubkey,
        "signature": signature,
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    r_response = data_object['response']
    r_signature = data_object['signature']

    if r_response == 'ok' and r_signature == 'ok':
        return 'ok'
    elif r_response == 'ok' and r_signature != 'ok':
        return data_object['signature']
    elif r_response == 'error':
        return data_object['message']


def report_user_status(username, password, status='online'):
    """
    Informs the login server about connection information for the user
    """
    host = cherrypy.config.get('server.socket_host')
    port = cherrypy.config.get('server.socket_port')
    connection_address = f'{host}:{port}'
    connection_location = '2'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
    keys = security_helper.get_keys()  # FOR TESTING PURPOSES

    url = 'http://cs302.kiwi.land/api/report'

    headers = api_helper.create_header(username, password)

    payload = {
        'connection_address': connection_address,
        'connection_location': connection_location,
        'incoming_pubkey': keys['pubkey'],
        'status': status,
    }

    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    return data_object['response']


def load_new_apikey(username, password):
    """
    Returns a new API key for authentication for the rest of the session
    Note: implemented for future use
    """
    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    url = 'http://cs302.kiwi.land/api/load_new_apikey'

    headers = api_helper.create_header(username, password)
    data_object = api_helper.get_data(url, headers=headers)

    return data_object


def server_pubkey():
    """
    Returns the public key of the login server
    """
    url = 'http://cs302.kiwi.land/api/loginserver_pubkey'

    data_object = api_helper.get_data(url)
    pubkey = data_object['pubkey']
    return pubkey


def list_apis():
    """
    Lists the APIs supported by the login server
    """
    url = 'http://cs302.kiwi.land/api/list_apis'

    data_object = api_helper.get_data(url)
    json_data = json.dumps(data_object, indent=4)
    print(json_data)

    return data_object
