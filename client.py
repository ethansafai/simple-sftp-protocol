from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import secrets
import socket

from ftp import client, shared

# create a 24-byte symmetric key
symmetric_key = secrets.token_bytes(24)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('localhost', shared.PORT))

# encrypt generated symmetric key with server's public key and send to server
server_public_key = sock.recv(1024)
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(server_public_key))
encrypted_symmetric_key = cipher_rsa.encrypt(symmetric_key)
sock.sendall(encrypted_symmetric_key)

while True:
    # receive user input
    request = input('ftp> ')

    if request == shared.LS_CMD:
        # handle ls command
        client.handle_ls(sock, symmetric_key)
    elif request == shared.QUIT_CMD:
        # handle quit command
        client.handle_quit(sock)
    else:
        # parse request
        arg_list = request.split(' ')
        # handle incorrectly formatted request
        if len(arg_list) != 2:
            print('BAD REQUEST')
            continue

        # split request into command and file name
        cmd, file_name = arg_list

        if cmd == shared.GET_CMD:
            # handle get command
            client.handle_get(sock, file_name, symmetric_key)
        elif cmd == shared.PUT_CMD:
            # handle put command
            client.handle_put(sock, file_name, symmetric_key)
        else:
            print('BAD REQUEST')
