import urllib.request
import json
import base64


def getData(url, headers, data=None):
    """
    Retrieves data from API endpoint
    """
    try:
        if data == None:
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
    
