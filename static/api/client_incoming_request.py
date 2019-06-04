import json
import time

import static.utils.api_helper as api_helper
import static.utils.security_helper as security_helper


def broadcast(login_server_record, message, sender_created_at, signature):
    """
    Transmits a signed broadcast between users
    """
    loginserver_record = 'wyao332,69592f14f52422ecf713b21f1615da2fec7d67eb7f0a8c4d3a72121d8e49cb66,1559114951.7035556,d0a5992d76f5f5464ddc0a530d8ea5f8a99b0fde4e0a3d4b91d100b7515188929ef22801420f25cc0b0f51095fa8cd9fbe6d3c93e1a93b7b2857cafdd6159a0e'
    ts = '1559114951.7035556'
    message = ':.:'
    keys = security_helper.get_keys(
        loginserver_record + message + str(ts))  # FOR TESTING PURPOSES
    signature = keys['signature']

    data_object = {
        'response': 'ok'
    }
    json_object = json.dumps(data_object)

    return json_object


def private_message(login_server_record, target_pubkey, target_username, encrypted_message, sender_created_at, signature):
    """
    Transmits a secret message between users.
    """
    pass


def check_messages(since):
    """
    Retrieve already-sent messages from other clients in the network
    """
    pass


def ping_check(my_time, my_active_usernames, connection_address, connection_location):
    """
    Checks is another client is active
    """
    pass


def group_message(login_server_record, group_key_hash, group_message, sender_created_at, signature):
    """
    Transmits a secret group message between users
    """
    pass


def group_invite(login_server_record, group_key_hash, target_pubkey, targer_username, encrypted_group_key, sender_created_at, signature):
    """
    Transmits a secret group message between users
    """
    pass
