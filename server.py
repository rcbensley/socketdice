#!/usr/bin/env python3

import argparse
import os
import random
import re
import socket
import sys
import threading
from collections import deque
from datetime import datetime as dt

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
    "for pitiful roles",
    "for critical fails",
    "for the murder hobos to ride again",
    "for the adventure toddlers",
    "for the Bard to TPK...again,",
    "for your epic nat 20's! Nah just kidding, it's a 1 again",
    "to rig the DC for all charisma builds",
    "for them to talk themselves outta this one",
    "the party to just opt for violence, again",
    "for really cautious and careful decisions",
    "for these amateurs to just meta it",
    "to see if they commit warcrimes",
]


def strip(s):
    return re.sub(r"[^A-Za-z0-9 ]+", "", s)


class Client:
    def __init__(self, client_id, addr, conn, name="unknown"):
        self.name = name
        self.id = client_id
        self.addr = addr
        self.conn = conn
        self.key = f"{addr[0]}:{addr[1]}"

    def send(self, msg: str):
        self.conn.sendall(f"{msg}\n".encode("utf-8"))

    def set_name(self, name: str):
        if name == self.name:
            return False
        self.name = name
        return True


class DiceServer:
    def __init__(self, host: str, port: int, password: str = None, max_rolls: int = 8):
        self.host = (host, port)
        self.password = password
        self.clients: dict[str, Client] = {}
        self.max_rolls = max_rolls
        self.lock = threading.Lock()
        self.commands = {
            "/roll": self.cmd_roll,
            "/dm": self.cmd_rolldm,
            "/name": self.cmd_name,
            "/who": self.cmd_who,
        }
        self.rolls = deque(maxlen=100)

    def log(self, message: str):
        now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{now} {message}")

    def _intro_server(self):
        i = SERVER_INTROS[random.randint(1, len(SERVER_INTROS) - 1)]
        return f"SOCKET DICE is listening {i}, on {self.host[0]}:{self.host[1]}"

    def broadcast(self, msg=""):
        with self.lock:
            m = msg.encode("utf-8") + b"\n"
            for k, v in self.clients.items():
                try:
                    v.send(m)
                except Exception as e:
                    self.log(f"broadcast error for {k}: {e}")

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
                self.log(f"Unknown roll format: {i}")
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

    def cmd_name(self, key: str, msg: str):
        new_name = " ".join(msg)
        for k, v in self.clients.items():
            if v.name == new_name and key == k:
                return
            if v.name == new_name and key != k:
                return
        if self.clients[key].set_name(new_name):
            self.log(f"{key} has changed their name to {self.clients[key].name}")

    def rollstr(self, msg):
        r = self.roll(msg)
        return ",".join(str(i) for i in r)

    def cmd_roll(self, key, msg, dm=False):
        result = self.rollstr(msg)
        name = self.clients[key].name
        prefix = "TO DM " if dm else ""
        log_msg = f"{prefix}{name} rolls {result}"
        self.log(log_msg)
        if not dm:
            self.broadcast(log_msg)
        to = "DM" if dm else "ALL"
        self.rolls.append({to: log_msg})

    def cmd_rolldm(self, key, msg):
        self.cmd_roll(key, msg, True)

    def client_key(self, addr):
        return f"{addr[0]}:{addr[1]}"

    def client_exists(self, addr):
        return self.client_key(addr) in self.clients

    def client_id_exists(self, client_id):
        for _, v in self.clients.items():
            if v.id == client_id:
                return True
        return False

    def client_add(self, conn, addr, name, client_id):
        with self.lock:
            if self.client_exists(addr):
                return False
            if self.client_id_exists(client_id):
                return False
            k = self.client_key(addr)
            c = Client(client_id=client_id, addr=addr, conn=conn, name=name)
            self.clients[k] = c
            self.log(f"Added client {c}:{client_id}")
        return True

    def cmd_exit(self, key: str):
        self.clients[key].send("Farewell")
        return False

    def cmd_who(self, key: str, _):
        names = ",".join([self.clients[i].name for i in self.clients])
        self.log(f"Connected player names: {names}")
        self.clients[key].send(names)

    def client_auth(self, conn, addr):
        if self.client_exists(addr):
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
                self.log(f"Wrong password {password}, from {name}@{addr}:{client_id}")
                return False
        self.client_add(conn, addr, name, client_id)
        self.log(f"{addr} has connected to the adventure")
        return True

    def client_handler(self, conn, addr):
        auth_ok = self.client_auth(conn, addr)
        if not auth_ok:
            conn.sendall("Login with /login name||id||password\n".encode("utf-8"))
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
            self.log(f"{addr} has rage quit")
        finally:
            with self.lock:
                if conn in self.clients:
                    self.clients.pop(conn, None)
            conn.close()
            self.log(f"{addr} has gone back to reality")

    def __call__(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(self.host)
        server.listen()
        print(HEADER)
        self.log(self._intro_server())
        try:
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self.client_handler, args=(conn, addr))
                thread.start()
                self.log(f"SOCKET DICE connections: {threading.active_count() - 1}")
        except KeyboardInterrupt:
            self.log("\nSOCKET DICE has stopped")
            server.close()
            sys.exit(0)
        server.close()
        sys.exit(0)


def main():
    cfg = {
        "host": os.getenv("DICEHOST", "0.0.0.0"),
        "port": os.getenv("DICEPORT", "5001"),
        "password": os.getenv("DICEPASS", ""),
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
        p = int(args.port)
    except (ValueError, TypeError):
        print(f"Unknown port value: {args.port}")
        sys.exit(1)
    try:
        ds = DiceServer(
            host=args.host,
            port=p,
            password=args.password,
        )
        ds()
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
