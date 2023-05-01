from __future__ import annotations
import socket

from ftp import shared

def get_ephemeral_socket() -> tuple[socket.socket, int]:
    """Creates an ephemeral socket for the data connection"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', 0))
    return sock, sock.getsockname()[1]

def open_data_port(control_conn: socket.socket) -> socket.socket:
    """Opens a data connection and returns the new socket"""
    # open data port and wait for server to connect
    new_socket, port = get_ephemeral_socket()
    new_socket.listen()
    control_conn.sendall(str(port).encode())
    data_conn, _ = new_socket.accept()

    new_socket.shutdown(socket.SHUT_RDWR)
    new_socket.close()

    return data_conn

def handle_get(conn: socket.socket, file_name: str, symmetric_key: bytes):
    """Sends a get command to the server and stores the received file on the
    client"""
    # send get command
    conn.sendall(f'{shared.GET_CMD} {file_name}'.encode())
    server_response = conn.recv(1024).decode()

    print('server:', server_response)
    if server_response != shared.PORT_CMD:
        print('server unwilling to connect')
        return
    
    # open data port and wait for server to connect
    data_conn = open_data_port(conn)
    print('server connected')

    # receive the file encoding
    encoding = conn.recv(1024).decode()
    print('server:', encoding)

    # receive and decrypt file data
    plain_text = shared.recv_and_decrypt(data_conn, symmetric_key)

    data_conn.shutdown(socket.SHUT_RDWR)
    data_conn.close()

    file_data = plain_text.decode(encoding)
    print('FILE DATA:')
    print(file_data)

    print('server:', conn.recv(1024).decode())

    # store the file
    f = open(f'client_files/{file_name}', 'w', encoding=encoding)
    f.write(file_data)

def handle_put(conn: socket.socket, file_name: str, symmetric_key: bytes):
    """Sends a file to the server to be stored"""
    try:
        # open and read the file
        f = open( f'client_files/{file_name}')
        data = f.read()

        # send put command
        conn.sendall(f'{shared.PUT_CMD} {file_name}'.encode())
        server_response = conn.recv(1024).decode()

        print('server:', server_response)
        if server_response != shared.PORT_CMD:
            print('server unwilling to connect')
            return
        
        # open data port and wait for server to connect
        data_conn = open_data_port(conn)

        # send the file encoding
        conn.sendall(f.encoding.encode())

        # encrypt and send file data
        shared.encrypt_and_send(data_conn, symmetric_key, data.encode())

        data_conn.shutdown(socket.SHUT_RDWR)
        data_conn.close()

        print('server:', conn.recv(1024).decode())
    except FileNotFoundError:
        print('client file not found')

def handle_ls(conn: socket.socket, symmetric_key: bytes):
    """Retrieves a list of files from the server"""
    # send ls command
    conn.sendall(shared.LS_CMD.encode())
    server_response = conn.recv(1024).decode()

    print('server:', server_response)
    if server_response != shared.PORT_CMD:
        print('server unwilling to connect')
        return
    
    # open data port and wait for server to connect
    data_conn = open_data_port(conn)

    # receive and decrypt file list
    plain_text = shared.recv_and_decrypt(data_conn, symmetric_key)

    data_conn.shutdown(socket.SHUT_RDWR)
    data_conn.close()

    file_list = plain_text.decode()
    print('FILE LIST:')
    print(file_list)

    print('server:', conn.recv(1024).decode())

def handle_quit(conn: socket.socket):
    """Closes the connection"""
    conn.sendall(shared.QUIT_CMD.encode())
    server_response = conn.recv(1024).decode()
    print('server:', server_response)
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()
    exit()
