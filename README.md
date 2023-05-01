# Simple Secure FTP Protocol

Uses socket programming, RSA asymmetric encryption, and AES symmetric encryption
to secure file data transfer between a client and a server. The core functionality for
the client, server, and encryption resides in the 'ftp' module.

## Langugae

- Python 3

## Usage

### Client

1. Invoking client.py by:

```bash
python3 client.py
```

will launch the client in interactive mode indicated by

```bash
ftp> [command]
```

From this mode the user can issue an FTP command with the following usage:

- ftp> GET [filename]
  - This will retrieve [filename] file from the server's filesystem to the client's filesystem
- ftp> PUT [filename]
  - This will send the [filename] file from the client filesystem to the server's
- ftp> LS
  - This will list all files in the server's filesystem
- ftp>> QUIT
  - This will stop the FTP session

### Server

Invoke server.py by:

```bash
python3 server.py
```

The server process will log to standard output

It is recommended to start the client and server processes in different terminals side by side to see the full operation of the FTP implementation
