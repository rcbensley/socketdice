#!/usr/bin/env python3

import argparse
import select
import socket
import sys
import uuid


def msg(m):
    return f"{m}\n".encode("utf-8")


def main(host, port, username, password):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.setblocking(False)
    username, password = username.strip(), password.strip()
    my_id = str(uuid.uuid1())
    auth_data = [i for i in ["/login", username, my_id, password] if i]
    auth_str = msg("||".join(auth_data))
    sock.sendall(auth_str)
    print("Connected")

    while True:
        try:
            read, _, _ = select.select([sock, sys.stdin], [], [])
            for i in read:
                if i is socket:
                    data = sock.recv(1024)
                    if not data:
                        print("closed")
                        sock.close()
                        sys.exit()
                    print(data.decode("utf-8").strip())
                elif i is sys.stdin:
                    m = msg(sys.stdin.readline().strip())
                    if m.lower().startswith(b"/quit"):
                        print("Quitting")
                        sock.close()
                        sys.exit()
                    sock.sendall(m)
        except KeyboardInterrupt:
            sock.close()
            sys.exit()
        except Exception as e:
            print(f"ERROR: {e}")
            sock.close()
            sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", default="127.0.0.1")
    parser.add_argument("-P", "--port", default=5001)
    parser.add_argument("-u", "--username", default="unknown")
    parser.add_argument("-p", "--password", default="")
    args = parser.parse_args()

    main(args.host, args.port, args.username, args.password)
