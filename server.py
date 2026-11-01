#!/usr/bin/env python3

import argparse
import os
import random
import re
import socket
import sys
import threading
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

NAMES = [
    "SPOOKY SKELETON",
    "THE BLOODY BARD",
    "WICKED WIZARD",
    "SKATEBOARDING SORCERER",
    "META PEST",
    "PROBABLE MIMIC",
    "TAVERN NPC No.3",
    "BLOODY BARBARIAN",
    "THE GREAT GOBO",
    "WIGGLY WARRIOR",
]
random.shuffle(NAMES)


def strip(s):
    return re.sub(r"[^A-Za-z0-9 ]+", "", s)


class Client:
    def __init__(self, addr, conn, name):
        self.name = name
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
    def __init__(self, host: str, port: int, password: str = None):
        self.host = (host, port)
        self.password = password
        self.clients = {}
        self.lock = threading.Lock()
        self.commands = {
            "/roll": self.cmd_roll,
            "/dm": self.cmd_rolldm,
            "/d": self.cmd_d_roll,
            "/dmd": self.cmd_rolldmd,
        }

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
        return results

    def cmd_d_roll(self, key, msg, dm=False):
        if not msg or len(msg) == 0:
            msg = [
                "1||20||0",
            ]
        try:
            d = msg[0].split("||", 3)
            if len(d) != 3:
                return
            count, sides, modifier = int(d[0]), int(d[1]), int(d[2])
        except (ValueError, TypeError):
            self.log("Incorrect /d roll format")
            return

        result = 0
        for _ in range(0, count):
            result += random.randint(1, sides)
        result += modifier
        name = self.clients[key].name
        prefix = "TO DM " if dm else ""
        log_msg = f"{prefix}{name} rolls {result}"
        self.log(log_msg)
        if not dm:
            self.broadcast(log_msg)

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

    def cmd_rolldm(self, key, msg):
        self.cmd_roll(key, msg, True)

    def cmd_rolldmd(self, key, msg):
        self.cmd_d_roll(key, msg, True)

    def client_key(self, addr):
        return f"{addr[0]}:{addr[1]}"

    def client_exists(self, addr):
        return self.client_key(addr) in self.clients

    def client_add(self, conn, addr):
        with self.lock:
            if self.client_exists(addr):
                return False
            cc = len(self.clients)
            if cc == len(NAMES):
                self.log("Max player count reached")
                return False
            name = NAMES[cc]
            k = self.client_key(addr)
            c = Client(addr=addr, conn=conn, name=name)
            self.clients[k] = c
            self.log(f"Added client {c}")
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

        login = data.split()
        if self.password and len(login) == 2:
            password = login[1]
            if password != self.password:
                self.log(f"Wrong password {password} {addr}")
                return False
        self.client_add(conn, addr)
        self.log(f"{addr} has connected to the adventure")
        return True

    def client_handler(self, conn, addr):
        auth_ok = self.client_auth(conn, addr)
        if not auth_ok:
            conn.sendall("Login with /login [password]\n".encode("utf-8"))
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


def main():
    cfg = {
        "host": os.getenv("DICEHOST", "0.0.0.0"),
        "port": os.getenv("DICEPORT", "5001"),
        "password": os.getenv("DICEPASS", ""),
    }
    parser = argparse.ArgumentParser()
    for k, v in cfg.items():
        parser.add_argument(f"--{k}", default=v)
    args = parser.parse_args()
    try:
        p = int(args.port)
    except (ValueError, TypeError):
        print(f"Unknown port value: {args.port}, must be an integer")
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
