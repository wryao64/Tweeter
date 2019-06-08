import urllib.request
import json
import base64
import socket


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

    Returns:
    data_object - type: object
    """
    data_object = None

    try:
        if headers == None and data == None:
            req = urllib.request.Request(url)
        elif data == None:
            req = urllib.request.Request(url, headers=headers)
        else:
            req = urllib.request.Request(url, data=data, headers=headers)

        response = urllib.request.urlopen(req, timeout=3)
        data = response.read()
        encoding = response.info().get_content_charset('utf-8')
        data_object = json.loads(data.decode(encoding))

        response.close()
    except urllib.error.HTTPError as error:
        data_object = {
            'response': 'error',
            'message': 'HTTPError: {}'.format(error.reason)
        }
    except urllib.error.URLError as error:
        data_object = {
            'response': 'error',
            'message': 'URLError: {}'.format(error.reason)
        }
    
    return data_object
