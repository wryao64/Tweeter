import json

import static.repositories.broadcast_repository as broadcast_repository
import static.repositories.private_message_repository as private_message_repository

def broadcast(loginserver_record, message, sender_created_at, signature):
    """
    Transmits a signed broadcast between users
    """
    # authenticate

    # send to database
    print("Message: " + message)
    broadcast_repository.post_broadcast(loginserver_record, message, sender_created_at, signature)

    data_object = {
        'response': 'ok'
    }
    # data_object = {
    #     'response': 'error',
    #     'message': 'Error: ###',
    # }
    json_object = json.dumps(data_object)

    return json_object


def private_message(loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature):
    """
    Transmits a secret message between users.
    """
    # authenticate

    # send to database
    private_message_repository.post_broadcast(loginserver_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature)

    data_object = {
        'response': 'ok'
    }
    # data_object = {
    #     'response': 'error',
    #     'message': 'Error: ###',
    # }
    json_object = json.dumps(data_object)

    return json_object


def check_messages(since):
    """
    Retrieve already-sent messages from other clients in the network

    Return:
    json_object - json-formatted string
    """

    # retrieve messages from database

    data_object = {
        'response': 'ok',
        'broadcasts': [],
        'private_messages': [],
    }
    json_object = json.dumps(data_object)
    
    return json_object


def ping_check(my_time, my_active_usernames, connection_address, connection_location):
    """
    Checks is another client is active
    """

    # check?

    data_object = {
        'response': 'ok'
    }
    # data_object = {
    #     'response': 'error',
    #     'message': 'Error: ###',
    # }
    json_object = json.dumps(data_object)

    return json_object


def group_message(loginserver_record, group_key_hash, group_message, sender_created_at, signature):
    """
    Transmits a secret group message between users
    """
    pass


def group_invite(loginserver_record, group_key_hash, target_pubkey, targer_username, encrypted_group_key, sender_created_at, signature):
    """
    Transmits a secret group message between users
    """
    pass
