from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import socket
import sys

from ftp import shared

def send_fail_msg(conn: socket.socket, msg: str):
    """Sends a failure message to the client"""
    conn.sendall(f'{shared.FAIL_MSG}: {msg}'.encode())

def setup_data_conn(conn: socket.socket, addr: str):
    """Sets up the data connection and returns the new socket"""
    try:
        conn.sendall(shared.PORT_CMD.encode())
        port = conn.recv(1024).decode()
        print('client:', port)
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_socket.connect((addr, int(port)))
        return new_socket
    except:
        # shut down
        sys.exit(1)

def handle_get(conn: socket.socket, addr: str, file_name: str, 
               symmetric_key: bytes):
    """Sends a file to the client"""
    try:
        f = open(f'server_files/{file_name}')
        data_conn = setup_data_conn(conn, addr)

        # read file data
        data = f.read()
        
        # send the file encoding
        conn.sendall(f.encoding.encode())

        # encrypt and send file data
        shared.encrypt_and_send(data_conn, symmetric_key, data.encode())

        data_conn.shutdown(socket.SHUT_RDWR)
        data_conn.close()

        conn.sendall(b'SUCCESS')
    except FileNotFoundError:
        send_fail_msg(conn, 'FILE NOT FOUND')

def handle_put(conn: socket.socket, addr: str, file_name: str, 
               symmetric_key: bytes):
    """Receives a file from the client and stores it on the server"""
    data_conn = setup_data_conn(conn, addr)

    encoding = conn.recv(1024).decode()
    print('client:', encoding)

    # receive and decrypt file data
    plain_text = shared.recv_and_decrypt(data_conn, symmetric_key)

    data_conn.shutdown(socket.SHUT_RDWR)
    data_conn.close()

    file_data = plain_text.decode(encoding)
    print('FILE DATA:')
    print(file_data)

    conn.sendall(b'SUCCESS')

    # store the file
    f = open(f'server_files/{file_name}', 'w', encoding=encoding)
    f.write(file_data)

def handle_ls(conn: socket.socket, addr: str, symmetric_key: bytes):
    """Sends the client a list of the files on the server"""
    data_conn = setup_data_conn(conn, addr)

    # get comma separated string of files
    files_list = ', '.join(os.listdir('server_files'))

    # encrypt and send the list of files
    shared.encrypt_and_send(data_conn, symmetric_key, files_list.encode())

    data_conn.shutdown(socket.SHUT_RDWR)
    data_conn.close()

    conn.sendall(b'SUCCESS')

def handle_quit(conn: socket.socket):
    """Closes the connection"""
    # send goodbye message and shut down the socket
    conn.sendall(b'BYE')
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()
    sys.exit()

def handle_request(conn: socket.socket, addr: str, server_key: RSA.RsaKey):
    """Parses and handles the client request"""
    # send client the server public key
    server_public_key = server_key.public_key().export_key()
    conn.sendall(server_public_key)

    # receive and decrypt client's symmetric key
    symmetric_key = conn.recv(1024)
    cipher_rsa = PKCS1_OAEP.new(server_key)
    decrypted_symmetric_key = cipher_rsa.decrypt(symmetric_key)

    while True:
        # receive client request
        request = conn.recv(1024).decode()
        print('client:', request)
        
        if request == shared.LS_CMD:
            # handle ls command
            handle_ls(conn, addr, decrypted_symmetric_key)
        elif request == shared.QUIT_CMD:
            # handle quit command
            handle_quit(conn)
        else:
            # parse request
            arg_list = request.split(' ')
            # handle incorrectly formatted request
            if len(arg_list) != 2:
                send_fail_msg(conn, 'BAD REQUEST')
                continue

            # split request into command and file name
            cmd, file_name = arg_list

            if cmd == shared.GET_CMD:
                handle_get(conn, addr, file_name, decrypted_symmetric_key)
            elif cmd == shared.PUT_CMD:
                handle_put(conn, addr, file_name, decrypted_symmetric_key)
            else:
                send_fail_msg(conn, 'BAD REQUEST')
