import nacl.encoding
import nacl.signing


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