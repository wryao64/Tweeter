import json
import time

import static.utils.api_helper as api_helper
import static.utils.security_helper as security_helper
import static.api.login_server as login_server


def broadcast(username, password, message):
    """
    Transmits a signed broadcast between users

    Returns:
    data_object - type: object
    """
    # url = 'http://127.0.0.1:1025/api/rx_broadcast'  # local
    # url = 'http://172.23.159.9:1025/api/rx_broadcast'  # uni
    # url = 'http://172.23.1.134:8080/api/rx_broadcast'  # Emily
    # url = 'http://cs302.kiwi.land/api/rx_broadcast'  # Hammond
    # url = 'http://172.23.69.234:80/api/rx_broadcast'  # James

    loginserver_record = login_server.get_loginserver_record(username, password)
    ts = time.time()

    prikey = login_server.get_privatekey(username, password)
    pubkey = security_helper.get_public_key(prikey)
    message_data = loginserver_record + message + str(ts)
    signature = security_helper.get_signature(prikey, pubkey, message_data=message_data)

    headers = api_helper.create_header(username, password)

    payload = {
        'loginserver_record': loginserver_record,
        'message': message,
        'sender_created_at': str(ts),
        'signature': signature,
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    # broadcast to everyone that's online
    try:
        users = login_server.list_users(username, password)

        for user in users:
            connection_address = user['connection_address']
            url = f'http:{connection_address}/api/rx_broadcast'
            data_object = api_helper.get_data(url, headers=headers, data=json_bytes)

            try:
                data_object = json.loads(data_object)
                print('{}: {}'.format(connection_address, data_object['response']))
            except json.decoder.JSONDecodeError:
                print('{}: {}'.format(connection_address, data_object))
    except TypeError:
        pass

    return 'ok'


def private_message(username, password, message):
    """
    Transmits a secret message between users.
    """
    url = 'http://127.0.0.1:1025/api/rx_privatemessage'
    # url = 'http://cs302.kiwi.land/api/rx_privatemessage'  # Hammond

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
    loginserver_record = 'wyao332,69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66,1559114951.7035556,d0a5992d76f5f5464ddc0a530d8ea5f8a99b0fde4e0a3d4b91d100b7515188929ef22801420f25cc0b0f51095fa8cd9fbe6d3c93e1a93b7b2857cafdd6159a0e'
    pubkey = '69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66'
    ts = '1559114951.7035556'
    # username = 'admin'
    # pubkey = '11c8c33b6052ad73a7a29e832e97e31f416dedb7c6731a6f456f83a344488ec0'

    keys = security_helper.get_keys(
        loginserver_record + pubkey + username + message + str(ts))  # FOR TESTING PURPOSES

    headers = api_helper.create_header(username, password)

    payload = {
        'loginserver_record': loginserver_record,
        'target_pubkey': pubkey,
        'target_username': username,
        'encrypted_message': message,
        'sender_created_at': str(ts),
        'signature': keys['signature'],
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    data_object = json.loads(data_object)

    return data_object


def check_messages(username, password):
    """
    Retrieve already-sent messages from other clients in the network

    Return:
    data_object - Python object
    """
    # url = 'http://127.0.0.1:1025/api/checkmessages'
    url = 'http://172.23.159.9:1025/api/checkmessages'

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
    ts = '1559114951.7035556'

    url += f'?since={ts}'

    headers = api_helper.create_header(username, password)
    data_object = api_helper.get_data(url, headers=headers)
    data_object = json.loads(data_object)

    return data_object


def ping_check(username, password):
    """
    Checks is another client is active
    """
    url = 'http://172.23.159.9:1025/api/ping_check'  # uni

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
    my_time = ''
    my_active_usernames = []
    connection_address = ''
    connection_location = ''

    headers = api_helper.create_header(username, password)

    payload = {
        'my_time': my_time,
        # 'my_active_usernames': my_active_usernames,
        'connection_address': connection_address,
        'connection_location': connection_location,
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    data_object = json.loads(data_object)

    return data_object


def group_message(username, password, message):
    """
    Transmits a secret group message between users
    """
    url = 'http://172.23.159.9:1025/api/rx_groupmessage'  # uni

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
    loginserver_record = 'wyao332,69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66,1559114951.7035556,d0a5992d76f5f5464ddc0a530d8ea5f8a99b0fde4e0a3d4b91d100b7515188929ef22801420f25cc0b0f51095fa8cd9fbe6d3c93e1a93b7b2857cafdd6159a0e'
    groupkey_hash = '69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66'
    ts = '1559114951.7035556'

    keys = security_helper.get_keys(
        loginserver_record + message + str(ts))  # FOR TESTING PURPOSES

    headers = api_helper.create_header(username, password)

    payload = {
        'loginserver_record': loginserver_record,
        'groupkey_hash': groupkey_hash,
        'group_message': message,
        'sender_created_at': str(ts),
        'signature': keys['signature'],
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    data_object = json.loads(data_object)

    return data_object


def group_invite(username, password, target_username):
    """
    Transmits a secret group message between users
    """
    url = 'http://172.23.159.9:1025/api/rx_groupinvite'  # uni

    username = "wyao332"  # FOR TESTING PURPOSES
    password = "wryao64_106379276"  # FOR TESTING PURPOSES
    loginserver_record = 'wyao332,69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66,1559114951.7035556,d0a5992d76f5f5464ddc0a530d8ea5f8a99b0fde4e0a3d4b91d100b7515188929ef22801420f25cc0b0f51095fa8cd9fbe6d3c93e1a93b7b2857cafdd6159a0e'
    groupkey_hash = '69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66'
    pubkey = '69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66'
    encrypted_groupkey = pubkey
    ts = '1559114951.7035556'

    keys = security_helper.get_keys(
        loginserver_record + groupkey_hash + pubkey + username + encrypted_groupkey + str(ts))  # FOR TESTING PURPOSES

    headers = api_helper.create_header(username, password)

    payload = {
        'loginserver_record': loginserver_record,
        'groupkey_hash': groupkey_hash,
        'target_pubkey': pubkey,
        'target_username': username,
        'encrypted_groupkey': pubkey,
        'sender_created_at': str(ts),
        'signature': keys['signature'],
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    data_object = json.loads(data_object)

    return data_object
