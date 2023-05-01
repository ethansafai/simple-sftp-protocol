from Crypto.PublicKey import RSA
import socket
import threading

from ftp import server, shared

# generate server public and private key
server_key = RSA.generate(2048)

# create server socket
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind(('', shared.PORT))

server_sock.listen(5)
print(f'server listening on port {shared.PORT}')

while True:
    # accept a connection
    conn, addr = server_sock.accept()
    print('client connected')
    
    # handle request on a new thread
    threading.Thread(
        target=server.handle_request, args=(conn, addr[0], server_key)
    ).start()
