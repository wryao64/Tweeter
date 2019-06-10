import json
import cherrypy

import static.utils.security_helper as security_helper
import static.repositories.broadcast_repository as broadcast_repository
import static.repositories.private_message_repository as private_message_repository
import static.repositories.group_message_repository as group_message_repository
import static.repositories.user_repository as user_repository
import static.api.login_server as login_server


def broadcast(loginserver_record, message, sender_created_at, signature):
    """
    Transmits a signed broadcast between users
    """
    # details of receiver
    details = user_repository.get_user()
    username = details[0]
    password = details[1]

    # details of sender
    record = loginserver_record.split(',')
    sender_pubkey = record[1]

    # check if details of sender matches
    response = login_server.check_pubkey(username, password, sender_pubkey)
    if response['response'] == 'ok':
        if response['loginserver_record'] == loginserver_record:
            # store in database
            broadcast_repository.post_broadcast(
                loginserver_record, message, sender_created_at, signature)

            data_object = {
                'response': 'ok'
            }
            cherrypy.log('Broadcast received')
        else:
            cherrypy.log('Login Server Record does not match')
            data_object = {
                'response': 'error',
                'message': 'Error: Login Server Record does not match',
            }
    else:
        cherrypy.log('Pubkey error (broadcast)')
        data_object = response

    return data_object


def private_message(loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature):
    """
    Transmits a secret message between users.
    """
    # details of receiver
    details = user_repository.get_user()
    username = details[0]
    password = details[1]
    priv_key = login_server.get_privatekey(username, password)

    # details of sender
    record = loginserver_record.split(',')
    sender_pubkey = record[1]

    # check if details of sender matches
    response = login_server.check_pubkey(username, password, sender_pubkey)
    if response['response'] == 'ok':
        if response['loginserver_record'] == loginserver_record:
            # decrypt message
            decrypted_message = security_helper.decrypt_message(priv_key, encrypted_message)

            # send to database
            private_message_repository.post_message(
                loginserver_record, target_pubkey, target_username, decrypted_message, sender_created_at, signature)
            
            data_object = {
                'response': 'ok'
            }
            cherrypy.log('Private message received')
        else:
            cherrypy.log('Login Server Record does not match')
            data_object = {
                'response': 'error',
                'message': 'Error: Login Server Record does not match',
            }
    else:
        cherrypy.log('Pubkey error (private message)')
        data_object = response

    return data_object


def check_messages(since):
    """
    Retrieve already-sent messages from other clients in the network

    Return:
    json_object - json-formatted string
    """

    # retrieve messages from database
    r_broadcasts = broadcast_repository.get_broadcasts(since)
    r_private_messages = private_message_repository.get_messages(since)

    broadcasts = []
    private_messages = []
    # convert to objects
    for b in r_broadcasts:
        broadcast = {
            'loginserver_record': b[0],
            'message': b[1],
            'sender_created_at': b[2],
            'signature': b[3],
        }
        broadcasts.append(broadcast)
    
    for p in r_private_messages:
        private_message = {
            'loginserver_record': p[0],
            'target_pubkey': p[1],
            'target_username': p[2],
            'encrypted_message': p[3],
            'sender_created_at': p[4],
            'signature': p[5],
        }
        private_messages.append(private_message)

    data_object = {
        'response': 'ok',
        'broadcasts': broadcasts,
        'private_messages': private_messages,
    }

    return data_object


def ping_check(my_time, connection_address, connection_location, my_active_usernames=None):
    """
    Checks if another client is active

    Return:
        data_object - object
    """
    if my_active_usernames != None:
        # get active users on this server

        data_object = {
            'response': 'ok',
            'my_active_usernames': [],
        }
    else:
        data_object = {
            'response': 'ok'
        }

    return data_object


def group_message(loginserver_record, groupkey_hash, group_message, sender_created_at, signature):
    """
    Transmits a secret group message between users
    """
    # authenticate

    # send to database
    group_message_repository.post_message(
        loginserver_record, groupkey_hash, group_message, sender_created_at, signature)

    data_object = {
        'response': 'ok'
    }
    # data_object = {
    #     'response': 'error',
    #     'message': 'Error: ###',
    # }

    return data_object


def group_invite(loginserver_record, groupkey_hash, target_pubkey, targer_username, encrypted_groupkey, sender_created_at, signature):
    """
    Transmits a secret group message between users
    """

    # store?

    data_object = {
        'response': 'ok'
    }
    # data_object = {
    #     'response': 'error',
    #     'message': 'Error: ###',
    # }

    return data_object
