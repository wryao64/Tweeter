import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

import static.utils.api_helper as api_helper
import static.utils.security_helper as security_helper


def add_privatedata(username, password, data):
    """
    Saves symmetrically encrypted private data for a user

    Return:
        data_object - object
    """
    url = 'http://cs302.kiwi.land/api/add_privatedata'

    key = 'strongkey'  # FOR TESTING PURPOSE: change to take user input

    # data = {
    #     'prikeys': ['cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'],
    #     'blocked_pubkeys': [],
    #     'blocked_usernames': [],
    #     'blocked_words': [],
    #     'blocked_message_signatures': [],
    #     'favourite_message_signatures': [],
    #     'friends_usernames': [],
    # }
    json_data = json.dumps(data)

    encrypted_data = security_helper.encrypt_data(key, json_data)

    loginserver_record = get_loginserver_record(
        username, password)
    ts = time.time()

    prikey = get_privatekey(username, password)
    pubkey = security_helper.get_public_key(prikey)
    message_data = encrypted_data + loginserver_record + str(ts)
    signature = security_helper.get_signature(
        prikey, pubkey, message_data=message_data)

    headers = api_helper.create_header(username, password)

    payload = {
        'privatedata': encrypted_data,
        'loginserver_record': loginserver_record,
        'client_saved_at': str(ts),
        'signature': signature,
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    return data_object


def add_pubkey(username, password):
    """
    Associates a public key with the user's account

    Return:
        data_object - object
    """
    url = "http://cs302.kiwi.land/api/add_pubkey"

    # generate new private key
    prikey = security_helper.generate_private_key()

    # upload private key to privatedata
    private_data = get_privatedata(username, password)
    (private_data['prikeys'])[0] = prikey
    add_privatedata(username, password, private_data)

    pubkey = security_helper.get_public_key(prikey)
    signature = security_helper.get_signature(
        prikey, pubkey, username=username)

    headers = api_helper.create_header(username, password)

    payload = {
        'pubkey': pubkey,
        'username': username,
        'signature': signature,
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    return data_object


def check_pubkey(username, password, pubkey):
    """
    Loads the loginserver_record for a given public key

    Return:
        data_object - object
    """
    url = "http://cs302.kiwi.land/api/check_pubkey?pubkey={}".format(pubkey)

    headers = api_helper.create_header(username, password)

    data_object = api_helper.get_data(url, headers=headers)
    return data_object


def get_loginserver_record(username, password):
    """
    Loads the user's current loginserver_record for use in creating point-to-point messages.

    Return:
        data_object - object
    """
    url = 'http://cs302.kiwi.land/api/get_loginserver_record'

    headers = api_helper.create_header(username, password)

    data_object = api_helper.get_data(url, headers=headers)
    return data_object


def get_privatedata(username, password):
    """
    Loads the saved symmetrically encrypted private data of the user

    Return:
        privatedata - decrypted data as Python object
        Or if error, Python object with error message
    """
    url = 'http://cs302.kiwi.land/api/get_privatedata'

    key = 'strongkey'  # FOR TESTING PURPOSE: change to take user input

    headers = api_helper.create_header(username, password)

    data_object = api_helper.get_data(url, headers=headers)

    if data_object['response'] == 'ok':
        encrypted_data = data_object['privatedata']
        decrypted_data = security_helper.decrypt_data(key, encrypted_data)
        privatedata = json.loads(decrypted_data)

        return privatedata
    else:
        return {
            'response': 'error',
            'message': data_object['message']
        }


def get_privatekey(username, password):
    """
    FOR INTERNAL USE ONLY
    """
    try:
        prikey = get_privatedata(username, password)['prikeys'][0]
    except KeyError:  # for testing purposes
        prikey = '69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66'
    return prikey


def list_users(username, password):
    """
    Lists the connection details for all active users within the last five minutes

    Return:
        users - Python object
    """
    url = 'http://cs302.kiwi.land/api/list_users'

    headers = api_helper.create_header(username, password)

    data_object = api_helper.get_data(url, headers=headers)

    if data_object['response'] == 'ok':
        return data_object
    else:
        return {
            'response': 'error',
            'message': data_object['message']
        }


def login(username, password):
    """
    User sign in
    """
    ping_response = ping(username, password)

    if ping_response['response'] == 'ok':
        response = report_user_status(username, password, 'online')
        return response
    else:
        return ping_response


def logout(username, password):
    """
    User sign out
    """
    response = report_user_status(username, password, 'offline')
    return response


def ping(username, password):
    """
    Checks if the login server is online and authenticates login

    Return:
        data_object - object
    """
    url = 'http://cs302.kiwi.land/api/ping'

    prikey = get_privatekey(username, password)
    pubkey = security_helper.get_public_key(prikey)
    signature = security_helper.get_signature(prikey, pubkey)

    headers = api_helper.create_header(username, password)

    payload = {
        "pubkey": pubkey,
        "signature": signature,
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    return data_object


def report_user_status(username, password, status='online'):
    """
    Informs the login server about connection information for the user

    Return:
        data_object - Python object
    """
    url = 'http://cs302.kiwi.land/api/report'

    host = cherrypy.config.get('server.socket_host')
    port = cherrypy.config.get('server.socket_port')
    connection_address = '{}:{}'.format(host, port)
    connection_location = '2'

    prikey = get_privatekey(username, password)
    pubkey = security_helper.get_public_key(prikey)

    headers = api_helper.create_header(username, password)

    payload = {
        'connection_address': connection_address,
        'connection_location': connection_location,
        'incoming_pubkey': pubkey,
        'status': status,
    }

    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    return data_object


def load_new_apikey(username, password):
    """
    Returns a new API key for authentication for the rest of the session
    Note: implemented for future use

    Return:
        data_object - object
    """
    url = 'http://cs302.kiwi.land/api/load_new_apikey'

    headers = api_helper.create_header(username, password)
    data_object = api_helper.get_data(url, headers=headers)
    return data_object


def server_pubkey():
    """
    Returns the public key of the login server

    Return:
        data_object - object
    """
    url = 'http://cs302.kiwi.land/api/loginserver_pubkey'

    data_object = api_helper.get_data(url)
    return data_object


def list_apis():
    """
    Lists the APIs supported by the login server
    """
    url = 'http://cs302.kiwi.land/api/list_apis'

    data_object = api_helper.get_data(url)

    return data_object
