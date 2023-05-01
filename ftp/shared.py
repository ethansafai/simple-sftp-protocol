from Crypto.Cipher import AES
import socket

GET_CMD = 'GET'
PUT_CMD = 'PUT'
LS_CMD = 'LS'
QUIT_CMD = 'QUIT'
PORT_CMD = 'PORT'
FAIL_MSG = 'FAIL'
SIZE_BYTES = 10
PORT = 8000

def pad_left_zeros(msg: str, length: int) -> str:
    """Pads msg with zeros on the left until msg has length bytes and returns
    the new msg"""
    # keep padding the string on the left with 0's until it has the specified
    # length
    while len(msg) < length:
        msg = '0' + msg
    return msg

def recv_all(sock: socket, num_bytes: int) -> bytearray:
    """Receives from sock until num_bytes have been read, returns the received
    bytes"""
    recv_buff = bytearray()
    buff_size = num_bytes

    # keep receiving until all bytes are received
    while len(recv_buff) < num_bytes:
        tmp_buff = sock.recv(num_bytes)

        # other side has closed the socket
        if not tmp_buff:
            break

        # add the received bytes to the buffer
        recv_buff.extend(tmp_buff)

        if len(recv_buff) == num_bytes:
            break

        # don't read in more bytes than num_bytes!
        if num_bytes - len(recv_buff) < buff_size:
            buff_size = num_bytes - len(recv_buff)

    return recv_buff

def encrypt_and_send(conn: socket.socket, symmetric_key: bytes, data: bytes):
    """Encrypts and sends data through conn using symmetric_key and AES"""
    # encrypt data
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    cipher_text, tag = cipher_aes.encrypt_and_digest(data)

    # send encrypted data along with the generated nonce and computed tag
    conn.sendall(
        # send length of nonce
        pad_left_zeros(str(len(nonce)), SIZE_BYTES).encode()
    )
    conn.sendall(nonce)
    conn.sendall(
        # send length of tag
        pad_left_zeros(str(len(tag)), SIZE_BYTES).encode()
    )
    conn.sendall(tag)
    conn.sendall(
        # send length of cipher_text
        pad_left_zeros(str(len(cipher_text)), SIZE_BYTES).encode()
    )
    conn.sendall(cipher_text)

def recv_and_decrypt(conn: socket.socket, symmetric_key: bytes) -> bytes:
    """Receives and decrypts file data from conn using symmetric_key and AES.
    Throws MacMismatchError if computed tag does not match due to tampering or
    use of an incorrect key."""
    # receive nonce
    nonce_length = recv_all(conn, SIZE_BYTES).decode()
    nonce = recv_all(conn, int(nonce_length))
    
    # receive tag
    tag_length = recv_all(conn, SIZE_BYTES).decode()
    tag = recv_all(conn, int(tag_length))

    # receive data
    data_length = recv_all(conn, SIZE_BYTES).decode()
    cipher_text = recv_all(conn, int(data_length))

    # decrypt data
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher_aes.decrypt_and_verify(cipher_text, tag)
    
    # return decrypted data
    return plain_text
