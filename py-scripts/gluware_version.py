#!/usr/bin/python3
import sys
from json import loads
from ssl import CERT_NONE
from websocket import WebSocket
from websocket import _exceptions as ws_exception

def get_gluware_version(addr):
    message = None
    ssl_cert_off = {"cert_reqs": CERT_NONE}

    # Turn off SSL certificate checking
    ws = WebSocket(sslopt=ssl_cert_off)

    try:
        ws.connect(
            'wss://{address}/ControlApi/socket.io/?EIO=3&transport=websocket'.format(
                address=addr))
    except ws_exception.WebSocketBadStatusException as con_error:
        print('Connection error: {info}'.format(info=con_error))
        return

    ws.send(
        '421["request",{"service":"DocsService","method":"getVersion","payload":{}}]')

    while True:
        message = ws.recv()
        #print(message)
        if not message:
            print('Empty message')
            return
        if 'gluware_version' in message:
            break

    json_string = message[4:-1]
    json_payload = loads(json_string)['payload']
    payload = loads(json_payload)
    return payload['gluware_version']['semver']

def main():
	if len(sys.argv) == 1:
		print('Usage: {filename} <address>'.format(filename=sys.argv[0]))
		sys.exit(1)
	return get_gluware_version(sys.argv[1])

if __name__ == '__main__':
	print(main())
  
