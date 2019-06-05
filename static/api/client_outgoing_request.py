import json
import time

import static.utils.api_helper as api_helper
import static.utils.security_helper as security_helper


def broadcast(username, password, message):
    """
    Transmits a signed broadcast between users
    """
    url = 'http://192.168.1.63:1025/api/rx_broadcast'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
    loginserver_record = 'wyao332,69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66,1559114951.7035556,d0a5992d76f5f5464ddc0a530d8ea5f8a99b0fde4e0a3d4b91d100b7515188929ef22801420f25cc0b0f51095fa8cd9fbe6d3c93e1a93b7b2857cafdd6159a0e'
    ts = '1559114951.7035556'

    keys = security_helper.get_keys(
        loginserver_record + message + str(ts))  # FOR TESTING PURPOSES

    headers = api_helper.create_header(username, password)

    payload = {
        'loginserver_record': loginserver_record,
        'message': message,
        'sender_created_at': str(ts),
        'signature': keys['signature'],
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    json_object = json.loads(data_object)

    return json_object


def private_message(username, password):
    """
    Transmits a secret message between users.
    """
    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES


def check_messages(username, password):
    """
    Retrieve already-sent messages from other clients in the network
    """
    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES


def ping_check(username, password):
    """
    Checks is another client is active
    """
    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES


def group_message(username, password):
    """
    Transmits a secret group message between users
    """
    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES


def group_invite(username, password):
    """
    Transmits a secret group message between users
    """
    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
