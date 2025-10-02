#!/usr/bin/env python3

import argparse
import os
import random
import re
import socket
import sys
import threading

ROLL_PATTERN = re.compile(r"^(\d*)d(\d+)([+-]\d+)?$")

# Font from:
# https://github.com/xero/figlet-fonts/blob/master/Bloody.flf
# toilet -f Bloody "Socket Dice"
HEADER = """
  ██████▒█████ ▄████▄ ██ ▄█▓████▄▄▄████  ▓█████▄ ██▓▄████▄▓█████
▒██    ▒██▒  █▒██▀ ▀█ ██▄█▒▓█   ▓  ██▒   ▒██▀ ██▓██▒██▀ ▀█▓█   ▀
░ ▓██▄ ▒██░  █▒▓█    ▓███▄░▒███ ▒ ▓██░   ░██   █▒██▒▓█    ▒███
  ▒   █▒██   █▒▓▓▄ ▄█▓██ █▄▒▓█  ░ ▓██▓   ░▓█▄   ░██▒▓▓▄ ▄█▒▓█  ▄
▒██████░ ████▓▒ ▓███▀▒██▒ █░▒████▒▒██▒   ░▒████▓░██▒ ▓███▀░▒████▒
▒ ▒▓▒ ▒░ ▒░▒░▒░ ░▒ ▒ ▒ ▒▒ ▓░░ ▒░ ░▒ ░░    ▒▒▓  ▒░▓ ░ ░▒ ▒ ░░ ▒░ ░
░ ░▒  ░  ░ ▒ ▒░ ░  ▒ ░ ░▒ ▒░░ ░  ░  ░     ░ ▒  ▒ ▒ ░ ░  ▒  ░ ░  ░
░  ░  ░░ ░ ░ ▒░      ░ ░░ ░   ░   ░       ░ ░  ░ ▒ ░         ░
      ░    ░ ░░ ░    ░  ░     ░  ░          ░    ░ ░ ░       ░  ░
              ░                           ░        ░
"""

SERVER_INTROS = [
    "pitiful roles",
    "critical fails",
    "the murder hobos to ride again",
    "the adventure toddlers",
    "the Bard to TPK...again,",
    "your nat 20's! Nah just kidding, it's a 1 again",
    "to rig the DC for all charisma builds",
    "them to talk themselves outta this one",
    "the party to just opt for violence, again, ",
    "to be really cautious and careful in their decisions",
    "these amateurs to just meta it",
]


def strip(s):
    return re.sub(r"[^A-Za-z0-9 ]+", "", s)


class DiceServer:
    def __init__(
        self, name: str, host: str, port: int, password: str = None, max_rolls=8
    ):
        self.name = strip(name)
        self.host = host
        self.port = port
        self.password = password
        self.clients = {}
        self.ids = {}
        self.max_rolls = max_rolls
        self.lock = threading.Lock()
        self.commands = {
            "/roll": self.cmd_roll,
            "/dm": self.cmd_rolldm,
            "/name": self.cmd_name,
        }

    def log(self, level: str, message: str):
        print(f"{level}\t{message}")

    def err(self, message: str):
        self.log("ERROR", message)

    def info(self, message: str):
        self.log("INFO", message)

    def _intro_server(self):
        i = SERVER_INTROS[random.randint(1, len(SERVER_INTROS) - 1)]
        return f"SOCKET DICE is listening for {i} on {self.host}:{self.port}"

    def broadcast(self, msg=""):
        with self.lock:
            m = msg.encode("utf-8") + b"\n"
            for i in self.clients:
                try:
                    self.clients[i]["conn"].sendall(m)
                except Exception as e:
                    self.err(f"broadcast error for {i}: {e}")

    def cmd_name(self, key, name):
        new_name = " ".join(name)
        old_name = self.client_name(key)
        if new_name == old_name:
            return
        self.info(f"{key} has changed their name from {old_name} to {new_name}")
        self.clients[key]["name"] = new_name

    def roll(self, msg):
        if not msg or len(msg) == 0:
            result = [
                random.randint(1, 20),
            ]
            return result
        results = []
        for i in msg:
            match = ROLL_PATTERN.match(i.strip())
            if not match:
                self.err(f"Unknown roll format: {i}")
                continue

            num, sides, modifier = match.groups()
            num = int(num) if num else 1
            sides = int(sides)
            modifier = int(modifier) if modifier else 0

            if num <= 0 or sides <= 0:
                continue

            rolls = [random.randint(1, sides) for _ in range(num)]
            total = sum(rolls) + modifier
            results.append(total)
        return results[: self.max_rolls]

    def client_name(self, key: str):
        if key in self.clients:
            pn = self.clients[key]["name"]
            return pn
        self.err(f"client_name not found for {key} in {self.clients}")
        return False

    def client_send(self, conn, msg):
        conn.sendall(f"{msg}\n".encode("utf-8"))

    def rollstr(self, msg):
        r = self.roll(msg)
        return ",".join(str(i) for i in r)

    def cmd_roll(self, key, msg, dm=False):
        result = self.rollstr(msg)
        name = self.client_name(key)
        to = "DM" if dm else "ALL"
        log_msg = f"{to}: {name} rolls {result}"
        self.log("ROLL", log_msg)
        if not dm:
            self.broadcast(log_msg)
        return result

    def cmd_rolldm(self, key, msg):
        self.cmd_roll(key, msg, True)

    def client_key(self, addr):
        return f"{addr[0]}:{addr[1]}"

    def client_add(self, conn, addr, name, client_id):
        with self.lock:
            if addr in self.clients:
                self.err(f"Address {addr} already exists for id {client_id}")
                return
            if client_id in self.ids:
                self.info(
                    f"Client ID {client_id} already exists for address {self.ids[client_id]}"
                )
                return
            c = self.client_key(addr)
            self.clients[c] = {
                "name": name,
                "addr": addr,
                "conn": conn,
            }
            self.ids[client_id] = c
            self.info(f"Added client {c} from {addr} with ID of {client_id}")

    def cmd_exit(self, key):
        self.clients[key]["conn"].sendall(b"Farewell\n")
        return False

    def client_auth(self, conn, addr):
        if addr in self.clients:
            return True
        data = conn.recv(1024).decode("utf-8").strip()
        if not data.startswith("/login"):
            return False

        login = data.split("||", 5)
        name = login[1]
        client_id = login[2]
        if self.password and len(login) == 4:
            password = login[4]
            if password != self.password:
                self.err(f"Wrong password {password}, from {name}@{addr}")
                return False
        self.client_add(conn, addr, name, client_id)
        self.info(f"{addr} has connected to the adventure")
        return True

    def client_handler(self, conn, addr):
        auth_ok = self.client_auth(conn, addr)
        if not auth_ok:
            return
        conn.sendall(b"ok\n")
        try:
            while True:
                data = conn.recv(1024).decode("utf-8").strip()
                if not data:
                    continue

                full_message = data.lower()
                m = full_message.split()
                if not m or len(m) == 0:
                    continue

                func = self.commands.get(m[0])
                msg = m[1:]
                key = self.client_key(addr)

                if func:
                    func(key, msg)
        except ConnectionResetError:
            self.info(f"{addr} has rage quit")
        finally:
            with self.lock:
                if conn in self.clients:
                    self.clients.pop(conn, None)
            conn.close()
            self.info(f"{addr} has gone back to reality")

    def __call__(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen()
        print(HEADER)
        self.info(self._intro_server())
        try:
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self.client_handler, args=(conn, addr))
                thread.start()
                self.info(f"SOCKET DICE connections: {threading.active_count() - 1}")
        except KeyboardInterrupt:
            self.info("\nSOCKET DICE has stopped")
            server.close()
            sys.exit(0)
        finally:
            server.close()
            sys.exit(0)


if __name__ == "__main__":
    cfg = {
        "host": os.getenv("DICEHOST", "0.0.0.0"),
        "port": os.getenv("DICEPORT", "5001"),
        "password": os.getenv("DICEPASS", ""),
        "name": os.getenv("DICENAME", "Socket Dice Game"),
        "log": os.getenv("DICELOG", None),
    }
    parser = argparse.ArgumentParser()
    for k, v in cfg.items():
        parser.add_argument(f"--{k}", default=v)
    parser.add_argument(
        "-r",
        "--reset",
        action="store_true",
        default=False,
        help="Reset the database and overwrite the log",
    )
    args = parser.parse_args()
    try:
        port = int(args.port)
    except (ValueError, TypeError):
        print(f"Unknown port value: {args.port}")
        sys.exit(1)
    try:
        ds = DiceServer(
            name=args.name,
            host=args.host,
            port=port,
            password=args.password,
        )
        ds()
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
