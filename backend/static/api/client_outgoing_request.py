import json
import time
import socket
import cherrypy

import static.utils.api_helper as api_helper
import static.utils.security_helper as security_helper
import static.api.login_server as login_server
import static.repositories.broadcast_repository as broadcast_repository
import static.repositories.private_message_repository as private_message_repository
import static.repositories.user_repository as user_repository


def broadcast(username, password, message):
    """
    Transmits a signed broadcast between users

    Returns:
        'ok' - string
    """
    loginserver_record = login_server.get_loginserver_record(username, password)[
        'loginserver_record']
    ts = time.time()

    prikey = login_server.get_privatekey(username, password)
    pubkey = security_helper.get_public_key(prikey)
    message_data = loginserver_record + message + str(ts)
    signature = security_helper.get_signature(
        prikey, pubkey, message_data=message_data)

    headers = api_helper.create_header(username, password)

    payload = {
        'loginserver_record': loginserver_record,
        'message': message,
        'sender_created_at': str(ts),
        'signature': signature,
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    # broadcast to everyone that's online
    users = login_server.list_users(username, password)['users']

    for user in users:
        connection_address = user['connection_address']

        # ping client to check if they are online
        response = ping_check(username, password, connection_address)
        try:
            if response['response'] != 'ok':
                cherrypy.log('{}: Ping error: {}'.format(
                    connection_address, response['message']))
                continue
        except KeyError:
            continue
        except TypeError:
            continue
        except json.decoder.JSONDecodeError:
            continue

        url = 'http://{}/api/rx_broadcast'.format(connection_address)

        data_object = api_helper.get_data(
            url, headers=headers, data=json_bytes)

        try:
            if data_object['response'] == 'ok':
                cherrypy.log('{}: {}'.format(
                    connection_address, data_object['response']))
            else:
                cherrypy.log('{}: {}'.format(
                    connection_address, data_object['message']))
        except TypeError:
            continue
        except KeyError:
            continue

    cherrypy.log('Broadcast sent')
    return 'ok'


def private_message(username, password, target_username, message):
    """
    Transmits a secret message between users.
    """
    # sender details
    loginserver_record = login_server.get_loginserver_record(username, password)[
        'loginserver_record']
    ts = time.time()

    # receiver details
    target_pubkey = user_repository.get_pubkey(target_username)

    isOnline = False

    # finds connection address of receiver
    connection_address = None
    users = login_server.list_users(username, password)['users']
    for user in users:
        if user['username'] == target_username:
            cherrypy.log('{} is online'.format(target_username))
            isOnline = True
            connection_address = user['connection_address']

            if target_pubkey != user['incoming_pubkey']:
                target_pubkey = user['incoming_pubkey']
                user_repository.post_user_info(target_username, target_pubkey)
                cherrypy.log('updated user\'s pubkey')
            break

    if target_pubkey != None:
        # encrypt message
        encrypted_message = security_helper.encrypt_message(target_pubkey, message)

        prikey = login_server.get_privatekey(username, password)
        pubkey = security_helper.get_public_key(prikey)
        message_data = loginserver_record + \
            target_pubkey + username + message + str(ts)
        signature = security_helper.get_signature(
            prikey, pubkey, message_data=message_data)

        headers = api_helper.create_header(username, password)

        payload = {
            'loginserver_record': loginserver_record,
            'target_pubkey': target_pubkey,
            'target_username': target_username,
            'encrypted_message': encrypted_message,
            'sender_created_at': str(ts),
            'signature': signature,
        }
        json_bytes = json.dumps(payload).encode('utf-8')

        # send message
        pingFailed = False
        if isOnline:
            # ping receiver to check if available
            response = ping_check(username, password, connection_address)

            if response['response'] != 'ok':
                cherrypy.log('{}: Ping error: {}'.format(
                    connection_address, response['message']))
                pingFailed = True

            if not pingFailed:
                # send to receiver
                url = 'http://{}/api/rx_privatemessage'.format(connection_address)

                data_object = api_helper.get_data(
                    url, headers=headers, data=json_bytes)
                cherrypy.log('Private message sent (recipient)')            

        # send to everyone else
        if not isOnline or pingFailed:
            for user in users:
                response = ping_check(username, password, user['connection_address'])

                try:
                    if response['response'] != 'ok':
                        cherrypy.log('{}: Ping error: {}'.format(
                            user['connection_address'], response['message']))
                        data_object = {
                            'response': 'error',
                            'message': 'Ping error'
                        }
                    else:
                        url = 'http://{}/api/rx_privatemessage'.format(
                            user['connection_address'])

                        data_object = api_helper.get_data(
                            url, headers=headers, data=json_bytes)

                        data_object = api_helper.get_data(
                            url, headers=headers, data=json_bytes)
                        cherrypy.log('{}: {}'.format(
                            user['connection_address'], data_object['response']))
                except TypeError:
                    continue
                except KeyError:
                    continue

            cherrypy.log('Private message sent (everyone)')
    else:
        cherrypy.log('No target pubkey')

        data_object = {
            'response': 'error',
            'message': 'No pubkey for target user'
        } 

    return data_object


def check_messages(username, password):
    """
    Retrieve already-sent messages from other clients in the network

    Return:
    data_object - Python object
    """
    headers = api_helper.create_header(username, password)

    # get time user was last online
    login_times = user_repository.get_login_times(username)
    last_online = login_times[-2][0]

    # broadcast to everyone that's online
    users = login_server.list_users(username, password)['users']
    # users = [{'connection_address': '127.0.0.1:1025'}]

    for user in users:
        connection_address = user['connection_address']

        # ping client to check if they are online
        response = ping_check(username, password, connection_address)
        if response['response'] != 'ok':
            cherrypy.log('{}: Ping error: {}'.format(
                connection_address, response['message']))
            continue

        url = 'http://{}/api/checkmessages?since={}'.format(
            connection_address, last_online)

        data_object = api_helper.get_data(
            url, headers=headers)

        if data_object['response'] == 'ok':
            broadcasts = data_object['broadcasts']
            private_messages = data_object['private_messages']

            # post new messages to database
            for b in broadcasts:
                broadcast_repository.post_broadcast(
                    b['loginserver_record'], b['message'], b['sender_created_at'], b['signature'])

            for p in private_messages:
                private_message_repository.post_message(
                    p['loginserver_record'], p['target_pubkey'], p['target_username'], p['encrypted_message'], p['sender_created_at'], p['signature'])

            cherrypy.log('{}: {}'.format(
                connection_address, data_object['response']))
        else:
            cherrypy.log('{}: {}'.format(
                connection_address, data_object['message']))

    return data_object


def ping_check(username, password, target_connection_address, my_active_usernames=None):
    """
    Checks if another client is active

    Return:
        data_object - object
    """
    url = 'http://{}/api/ping_check'.format(target_connection_address)

    my_time = time.time()
    host = cherrypy.config.get('server.socket_host')
    port = cherrypy.config.get('server.socket_port')
    connection_address = '{}:{}'.format(host, port)
    connection_location = '2'

    headers = api_helper.create_header(username, password)

    if my_active_usernames != None:
        payload = {
            'my_time': my_time,
            'my_active_usernames': my_active_usernames,
            'connection_address': connection_address,
            'connection_location': connection_location,
        }
    else:
        payload = {
            'my_time': my_time,
            'connection_address': connection_address,
            'connection_location': connection_location,
        }
    json_bytes = json.dumps(payload).encode('utf-8')

    data_object = api_helper.get_data(url, headers=headers, data=json_bytes)
    return data_object


def group_message(username, password, message):
    """
    Transmits a secret group message between users
    """
    url = 'http://172.23.159.9:1025/api/rx_groupmessage'  # uni

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
