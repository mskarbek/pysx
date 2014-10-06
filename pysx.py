#!/usr/bin/env python
import base64
import hashlib
from datetime import datetime
import hmac
import binascii
import sys
import json

import requests
import pytz

def hextobyte(hex_str):
    bytes = []
    hex_str = ''.join( hex_str.split(' ') )
    for i in range(0, len(hex_str), 2):
        bytes.append( chr( int (hex_str[i:i+2], 16 ) ) )
    return ''.join( bytes )

request = {
    'Date': datetime.now(pytz.timezone('GMT')).strftime('%a, %d %b %Y %H:%M:%S GMT'),
    'Path': '?nodeList',
    'Type': 'GET',
    'Body': ''
}

pysx = {}

pysx['IP'] = sys.argv[1]
pysx['Key'] = base64.b64decode(sys.argv[2])

pysx['I'] = ''.join(['%02X' % ord(x) for x in pysx['Key']]).strip()[0:40].lower()
pysx['K'] = pysx['Key'][20:40]
pysx['P'] = ''.join(['%02X' % ord(x) for x in pysx['Key']]).strip()[80:84].lower()

pysx['request'] = '{}\n{}\n{}\n{}\n'.format(
    request['Type'],
    request['Path'],
    request['Date'],
    hashlib.sha1(request['Body']).hexdigest()
)

pysx['H'] = hmac.new(pysx['K'], pysx['request'], hashlib.sha1).hexdigest()

pysx['A'] = base64.b64encode(hextobyte(pysx['I'] + pysx['H'] + pysx['P']))

headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'pysx 0.0.1',
    'Date': request['Date'],
    'Authorization': 'SKY {}'.format(pysx['A'])
}

response = requests.get('https://{}/{}'.format(pysx['IP'], request['Path']), verify = False, headers = headers)

print '\n{}\n'.format(response.request.url)
print '{}\n'.format(response.request.headers)
print '{}\n'.format(response.headers)
print '{}\n'.format(response.text)
