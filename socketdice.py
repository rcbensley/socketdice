#!/usr/bin/env python3

import os
import re
import sys
import socket
import random
import logging
import argparse
import threading

ROLL_PATTERN = re.compile(r"^(\d*)d(\d+)([+-]\d+)?$")
COMMANDS = b"Accepted commands: /roll, /cmd_rolldm, /quit, /exit\n"

client_name = "name"
client_addr = "addr"
client_conn = "conn"

# Font from:
# https://github.com/xero/figlet-fonts/blob/master/Bloody.flf
# toilet -f Bloody "Socket Dice"
HEADER="""
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

CLIENT_INTROS = []

def strip(s):
    return re.sub(r"[^A-Za-z0-9 ]+", "", s)

class Server:
    def __init__(self, name, host, port, password):
        self.name = strip(name)
        self.host = host
        self.port = port
        self.password = password
        self.running = True
        self.clients= {}
        self.lock = threading.Lock()
        self._init_log()
        self.commands = {
                "/roll": self.cmd_roll,
                "/rolldm": self.cmd_rolldm,
                "/name": self.cmd_name,
        }

    def _init_log(self):
        log_file_name = self.name.replace(" ", "_")
        self.logger = logging.getLogger("Socket Dice")
        log_fmt = logging.Formatter(
                f"%(asctime)s {self.name}: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S")
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(log_fmt)
        file_handler = logging.FileHandler(
                f"{log_file_name}.log",
                mode="a",
                encoding="utf-8")
        file_handler.setFormatter(log_fmt)
        self.logger.addHandler(stream_handler)
        self.logger.addHandler(file_handler)
        self.logger.setLevel(logging.INFO)

    def log(self, msg):
        self.logger.log(logging.INFO, msg)

    def _intro_client(self):
        return "client intro"

    def _intro_server(self):
        i = SERVER_INTROS[random.randint(1, len(SERVER_INTROS)-1)]
        return f"SOCKET DICE is listening for {i} on {self.host}:{self.port}"

    def broadcast(self, msg):
        with self.lock:
            m = msg.encode("utf-8") + b"\n"
            for i in self.clients:
                try:
                    self.clients[i][client_conn].sendall(m)
                except:
                    #self.clients.pop(i, None)
                    self.log(f"broadcast error for {i}")
                    pass

    def cmd_name(self, key, name):
        new_name = " ".join(name)
        new_name = strip(new_name)
        if new_name == name:
            return
        old_name = self.clients[key][client_name]
        self.log(f"{key} has changed their name from {old_name} to {new_name}")
        self.clients[key][client_name] = new_name

    def roll(self, msg):
        if not msg or len(msg) == 0:
            result = [random.randint(1, 20), ]
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

    def client_name(self, key):
        return self.clients[key][client_name]
    
    def rollstr(self, msg):
        r = self.roll(msg)
        return " ".join(str(i) for i in r)
    
    def cmd_roll(self, key, msg):
        r = self.rollstr(msg)
        m = f"{self.clients[key]['name']} rolls {r}"
        self.broadcast(m)
        return True

    def cmd_rolldm(self, key, msg):
        r = self.rollstr(msg)
        m = f"[TO DM], {self.client_name(key)} rolls {r}"
        self.log(m)
        self.clients[key][client_conn].sendall(m + b"\n")
        return True
   
    def client_key(self, addr):
        return f"{addr[0]}:{addr[1]}"

    def client_add(self, conn, addr):
        if addr in self.clients:
            return
        n = self.client_key(addr)
        self.clients[n] = {
                client_name: n,
                client_addr: addr,
                client_conn: conn,
        }
        self.log(f"Added client from {addr}")

    def cmd_exit(self, key, msg):
        self.clients[key][client_conn].sendall(b"Farewell\n")
        return False

    def client_handler(self, conn, addr):
        self.log(f"{addr} has connected to the adventure")
        with self.lock:
            self.client_add(conn, addr)
        conn.sendall(b"Welcome to SOCKET DICE\n")
        conn.sendall(COMMANDS)
        try:
            while True:
                data = conn.recv(1024).strip()
                if not data:
                    continue

                full_message = data.decode("utf-8").lower()
                m = full_message.split()
                if not m or len(m) == 0:
                    continue

                func = m[0]
                msg = m[1:]
                key = self.client_key(addr)

                if func in self.commands:
                    self.commands[func](key, msg)
                else:
                    conn.sendall(COMMANDS)
        except ConnectionResetError:
            self.log(f"{addr} has rage quit")
        finally:
            with self.lock:
                if conn in self.clients:
                    self.clients.pop(conn, None)
            conn.close()
            self.log(f"{addr} has gone back to reality")

    def __call__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        self.log(self._intro_server())
        try:
            while self.running:
                conn, addr = self.server.accept()
                thread = threading.Thread(target=self.client_handler, args=(conn, addr))
                thread.start()
                self.log(f"SOCKET DICE connections: {threading.active_count() - 1}")
        except KeyboardInterrupt:
            self.log("\nSOCKET DICE has stopped")
        finally:
            self.server.close()
            sys.exit()


if __name__ == "__main__":
    cfg = {
        "host": os.getenv("DICEHOST", "0.0.0.0"),
        "port": os.getenv("DICEPORT", 5001),
        "password": os.getenv("DICEPASS", ""),
        client_name: os.getenv("DICENAME", "Socket Dice Game"),
    }
    parser = argparse.ArgumentParser()
    for k, v in cfg.items():
        parser.add_argument(f"--{k}", default=v)
    args = parser.parse_args()
    
    try:
        port = int(args.port)
    except (ValueError, TypeError):
        self.log(f"Unknown port value: {args.port}")
        sys.exit(1)
    server = Server(args.name, args.host, port, args.password)
    print(HEADER)
    server()
