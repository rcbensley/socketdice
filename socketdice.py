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
COMMANDS = b"Accepted commands: /roll, /rolldm, /quit, /exit\n"

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
            for i in self.clients:
                try:
                    m = msg.encode("utf-8")
                    self.clients[i]["conn"].sendall(f"{m}\n")
                except:
                    #self.clients.pop(i, None)
                    self.log(f"broadcast error for {i}")
                    pass

    def set_name(self, addr, conn, name):
        new_name = " ".join(name)
        new_name = strip(new_name)
        if new_name == name:
            return
        self.log(f"{addr} has changed their name from {name} to {new_name}")
        self.clients[addr]["name"] = new_name

    def roll(self, input):
        if not input or len(input) == 0:
            result = [random.randint(1, 20), ]
            return result
        results = []
        for i in input:
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
    
    def rollstr(self, input):
        return " ".join(str(i) for i in self.roll(input))
    
    def rollall(self, addr, input):
        r = self.rollstr(input)
        m = f"{self.pname(addr)} rolls {r}"
        self.broadcast(m)

    def rolldm(self, conn, add, input):
        r = self.rollstr(input)
        m = f"[TO DM], {self.pname(addr)} rolls {r}"
        self.log(m)
        conn.sendall(m + b"\n")
    

    def client_add(self, conn, addr):
        if addr in self.clients:
            return
        self.clients[addr] = {
                "name": f"{addr[0]}:{addr[1]}",
                "addr": addr,
                "conn": conn,
        }
        self.log(f"Added client from {addr}")
        for i in self.clients.items():
            self.log(i)


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
                    break  # Disconnect

                full_message = data.decode("utf-8").lower()
                m = full_message.split()
                if not m or len(m) == 0:
                    continue

                cmd = m[0]
                msg = m[1:]

                if cmd in ("/exit", "/quit"):
                    conn.sendall(b"Farewell\n")
                    break
                elif cmd == "/name":
                    self.set_name(conn, addr, msg)
                elif cmd == "/rolldm":
                    self.rolldm(msg)
                elif cmd == "/roll":
                    self.broadcast(m)
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


if __name__ == "__main__":
    cfg = {
        "host": os.getenv("DICEHOST", "0.0.0.0"),
        "port": os.getenv("DICEPORT", 5001),
        "password": os.getenv("DICEPASS", ""),
        "name": os.getenv("DICENAME", "Socket Dice Game"),
    }
    parser = argparse.ArgumentParser()
    for k, v in cfg.items():
        parser.add_argument(f"--{k}", default=v)
    args = parser.parse_args()
    
    try:
        port = int(args.port)
    except (ValueError, TypeError):
        logging.error(f"Unknown port value: {args.port}")
        sys.exit(1)
    server = Server(args.name, args.host, port, args.password)
    print(HEADER)
    server()
