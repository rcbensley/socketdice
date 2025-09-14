#!/usr/bin/env python3

import os
import re
import sys
import select
import socket

def strip(s):
    return re.sub(r"[^A-Za-z0-9 ]+", "", s)

def msg(m):
    f"{m}\n".encode("utf-8")

def main(host, port, username, password):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host,port))
    sock.setblocking(False)
    username, password = username.strip(), password.strip()
    auth_str = f"/login\t{username}\t{password}"
    sock.sendall(msg(auth_str))
    print("Connected")

    while True:
        read, _, _ = select.select([sock, sys.stdin], [], [])

        for i in read:
            if i is socket:
                try:
                    data = sock.recv(1024)
                    if not data:
                        print("closed")
                        sock.close()
                        sys.exit()
                    print(data.decode("utf-8").strip())
                except Exception as e:
                    print(f"ERROR: {e}")
                    sock.close()
                    sys.exit()
            elif i is sys.stdin:
                m = msg(sys.stdin.readline().strip())
                if m.lower().startswith("/quit"):
                    print("Quitting")
                    sock.close()
                    sys.exit()
                sock.sendall(m)

if __name__ == "__main__":
    cfg = {
        "host": os.getenv("DICEHOST", "127.0.0.1"),
        "port": os.getenv("DICEPORT", 5001),
        "username": os.getenv("DICEUSER", ""),
        "password": os.getenv("DICEPASS", ""),
    }
    parser = argparse.ArgumentParser()
    for k, v in cfg.items():
        parser.add_argument(f"--{k}", default=v)
    args = parser.parse_args()

    main(args.host, args.port, args.username, args.password)
