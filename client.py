#!/usr/bin/env python3

import argparse
import select
import socket
import sys
import threading
import uuid


def msg(m):
    return f"{m}\n".encode("utf-8")


def listen(sock):
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                continue
            print(data.decode("utf-8").strip(), flush=True)
    except OSError:
        pass
    finally:
        sock.close()


def main(host, port, username, password):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.setblocking(False)
    listener = threading.Thread(target=listen, args=(sock,), daemon=True)
    listener.start()
    username, password = username.strip(), password.strip()
    my_id = str(uuid.uuid1())
    auth_data = [i for i in ["/login", username, my_id, password] if i]
    auth_str = msg("||".join(auth_data))
    sock.sendall(auth_str)
    print("Connected")

    try:
        while True:
            i = input("> ")
            if i.lower() in {"quit", "exit"}:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
                return
            sock.sendall((msg + "\n").encode())
    except KeyboardInterrupt:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", default="127.0.0.1")
    parser.add_argument("-P", "--port", default=5001)
    parser.add_argument("-u", "--username", default="unknown")
    parser.add_argument("-p", "--password", default="")
    args = parser.parse_args()
    main(args.host, args.port, args.username, args.password)
