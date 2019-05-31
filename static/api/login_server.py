import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time


"""
User sign in
"""
def login(username, password):
    # authenticate user
    isAuthenticated = ping(username, password)
    print("isAuthenticated: {0}".format(isAuthenticated))

    # check public/private keypair

    # test pub/priv keypair

    # report as online

    return 0


"""
User sign out
"""
def logout(username, password):
    # report as offline
    return 0


"""
Checks if the login server is online and authenticates login
"""
def ping(username, password):
    url = "http://cs302.kiwi.land/api/ping"

    username = "wyao332" # FOR TESTING PURPOSES
    password = "wryao64_106379276" # FOR TESTING PURPOSES

    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d' # FOR TESTING PURPOSES

    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

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

    try:
        req = urllib.request.Request(url, data=json_bytes, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()

        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

        return 1


def reportUserStatus(username, password, status='online'):
    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES

    # FOR TESTING PURPOSES
    print("Log on/off attempt from {0}:{1}\n".format(username, password))

    url = "http://cs302.kiwi.land/api/report"

    # FOR TESTING PURPOSES
    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

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

    try:
        req = urllib.request.Request(url, data=json_bytes, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        # load encoding if possible (default to utf-8)
        encoding = response.info().get_content_charset('utf-8')
        response.close()
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
        return 1
