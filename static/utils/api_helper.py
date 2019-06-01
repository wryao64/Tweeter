import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing


def create_header(username, password):
    """
    Create HTTP BASIC authorization header
    """
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    return headers


def get_data(url, headers=None, data=None):
    """
    Retrieves data from API endpoint
    """
    try:
        if headers == None and data == None:
            req = urllib.request.Request(url)
        elif data == None:
            req = urllib.request.Request(url, headers=headers)
        else:
            req = urllib.request.Request(url, data=data, headers=headers)
        
        response = urllib.request.urlopen(req)
        data = response.read()
        encoding = response.info().get_content_charset('utf-8')
        data_object = json.loads(data.decode(encoding))
        
        response.close()

        return data_object
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    
def get_keys(message_data=None, use_pubkey=False):
    """
    For testing: gets strings of pubkey, signature
    """
    # hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'
    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

    # Obtain the verify key for a given signing key
    pubkey = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')

    # Message
    # add_privatedata: encrypted_data + loginserver_record + ts (pass in)
    # add_pubkey: pubkey_hex_str + username
    # ping: pubkey_hex_str
    if message_data == None:
        message = pubkey_hex_str
    elif message_data != None and use_pubkey == True:
        message = pubkey_hex_str + message_data
    else:
        message = message_data

    message_bytes = bytes(message, encoding='utf-8')

    # Sign message with signing/private key
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    keys = {
        'pubkey': pubkey_hex_str,
        'signature': signature_hex_str,
    }

    return keys
