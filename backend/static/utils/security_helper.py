import base64
import nacl.encoding
import nacl.pwhash
import nacl.secret
import nacl.signing
import nacl.utils


def decrypt_data(key, data):
    """
    Decrypts user's private data
    """
    box = generate_secret_box(key)

    data_bytes = base64.b64decode(data)
    decrypted_str = box.decrypt(data_bytes).decode('utf-8')

    return decrypted_str


def encrypt_data(key, data):
    """
    Encrypts user's private data using Secret Key Encryption
    """
    box = generate_secret_box(key)

    # Encrypt data
    byte_data = bytes(data, encoding='utf-8')

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted_bytes = box.encrypt(byte_data, nonce=nonce)
    encrypted_str = base64.b64encode(encrypted_bytes).decode('utf-8')

    return encrypted_str


def generate_secret_box(key):
    """
    Generate secret box for Secret Key Encryption
    """
    key_password = bytes(key, encoding='utf-8')
    salt = (key_password * 16)[:16]
    sym_key = nacl.pwhash.argon2i.kdf(
        nacl.secret.SecretBox.KEY_SIZE, key_password, salt)

    box = nacl.secret.SecretBox(sym_key)

    return box


def get_keys(message_data=None, use_pubkey=False):
    """
    For testing: gets strings of pubkey, signature
    """
    # hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
    hex_key = b'cd7f971fc826eeb354c5ade4293b5e83a93c74c1aa624a2c28e6a14b97ae3d0d'
    signing_key = nacl.signing.SigningKey(
        hex_key, encoder=nacl.encoding.HexEncoder)

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


def get_public_key(prikey):
    """
    Retrieves user's public key

    Input:
        prikeys - 
    Return:
        pubkey_hex_str - string
    """
    signing_key = nacl.signing.SigningKey(
        prikey, encoder=nacl.encoding.HexEncoder)

    pubkey = signing_key.verify_key
    pubkey_hex = pubkey.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    
    return pubkey_hex_str


def get_signature(prikey, pubkey):
    """
    Processes signature from user's public key

    Input:
        prikey -
        pubkey - 
        message_data - 
    Return:
        signature - string
    """
    # if message_data == None:
    #     message = pubkey_hex_str
    # elif message_data != None and use_pubkey == True:
    #     message = pubkey_hex_str + message_data
    # else:
    #     message = message_data
    # message = pubkey + message_data  # pubkey + username
    message = pubkey

    message_bytes = bytes(message, encoding='utf-8')

    # Sign message with signing/private key
    signing_key = nacl.signing.SigningKey(
        prikey, encoder=nacl.encoding.HexEncoder)
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    return signature_hex_str
