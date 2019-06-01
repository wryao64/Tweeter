import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

import static.utils.api_helper as api_helper


def add_privatedata(username, password):
    """
    Saves symmetrically encrypted private data for a user
    """
    url = 'http://cs302.kiwi.land/api/add_privatedata'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    data = {
        'prikeys': [],
        'blocked_pubkeys': [],
        'blocked_usernames': [],
        'blocked_words': [],
        'blocked_message_signatures': [],
        'friends_usernames': [],
    }

    # encrypt data
    encrypted_data = data  # TODO: ENCRYPT

    loginserver_record = get_loginserver_record(username, password)
    ts = time.time()

    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

    # Obtain the verify key for a given signing key
    pubkey = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    # Message
    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')

    # Sign message with signing/private key
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    # create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        'privatedata': encrypted_data,
        'loginserver_record': loginserver_record,
        'client_saved_at': ts,
        'signature': signature_hex_str,
    }

    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.getData(url, headers=headers, data=json_bytes)
    return data_object


def add_pubkey(username, password):
    """
    Associates a public key with the user's account
    """
    url = "http://cs302.kiwi.land/api/add_pubkey"

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    # hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

    # Obtain the verify key for a given signing key
    pubkey = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    # Message
    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')

    # Sign message with signing/private key
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    # create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey": pubkey_hex_str,
        "username": username,
        "signature": signature_hex_str,
    }

    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.getData(url, headers=headers, data=json_bytes)
    return data_object


def check_pubkey(username, password):
    """
    Loads the loginserver_record for a given public key
    """
    url = "http://cs302.kiwi.land/api/check_pubkey"

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    # create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    # FOR TESTING PURPOSES
    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'
    signing_key = nacl.signing.SigningKey(
        hex_key, encoder=nacl.encoding.HexEncoder)

    # Obtain the verify key for a given signing key
    pubkey = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    url += "?pubkey=" + pubkey_hex_str

    data_object = api_helper.getData(url, headers=headers)
    return data_object


def get_loginserver_record(username, password):
    """
    Loads the user's current loginserver_record for use in creating point-to-point messages.
    """
    url = 'http://cs302.kiwi.land/api/get_loginserver_record'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    # create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    data_object = api_helper.getData(url, headers=headers)
    return data_object


def get_privatedata(username, password):
    """
    """


def list_online_users(username, password):
    """
    Lists the connection details for all active users within the last five minutes
    """
    url = 'http://cs302.kiwi.land/api/list_users'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    # create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    data_object = api_helper.getData(url, headers)
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

        isOk = report_user_status(username, password, 'online')
        if isOk == 'ok':
            return True
        else:
            return False
    else:
        return False


def logout(username, password):
    """
    User sign out
    """
    isOk = report_user_status(username, password, 'offline')
    if isOk == 'ok':
        return True
    else:
        return False


def ping(username, password):
    """
    Checks if the login server is online and authenticates login
    """
    url = 'http://cs302.kiwi.land/api/ping'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    # FOR TESTING PURPOSES
    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'

    signing_key = nacl.signing.SigningKey(
        hex_key, encoder=nacl.encoding.HexEncoder)

    # Obtain the verify key for a given signing key
    pubkey = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    # Sign pubkey with signing/private key
    pubkey_bytes = bytes(pubkey_hex_str, encoding='utf-8')
    signed = signing_key.sign(pubkey_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    # create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey": pubkey_hex_str,
        "username": username,
        "signature": signature_hex_str,
    }

    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.getData(url, headers, json_bytes)
    return data_object['response']


def report_user_status(username, password, status='online'):
    """
    Informs the login server about connection information for the user
    """
    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    # FOR TESTING PURPOSES
    print("Log on/off attempt from {0}:{1}\n".format(username, password))

    url = 'http://cs302.kiwi.land/api/report'

    # FOR TESTING PURPOSES
    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'
    signing_key = nacl.signing.SigningKey(
        hex_key, encoder=nacl.encoding.HexEncoder)

    # Obtain the verify key for a given signing key
    pubkey = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    # create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        "connection_address": "127.0.0.1:8000",
        "connection_location": "2",
        "incoming_pubkey": pubkey_hex_str,
        "status": status,
    }

    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.getData(url, headers, json_bytes)
    return data_object['response']


def server_pubkey():
    """
    Returns the public key of the login server
    """
    url = 'http://cs302.kiwi.land/api/loginserver_pubkey'

    data_object = api_helper.getData(url)
    pubkey = data_object['pubkey']
    return pubkey
