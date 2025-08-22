#!/usr/bin/env python3

import os
import re
import sys
import socket
import random
import logging
import argparse
import threading

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

ROLL_PATTERN = re.compile(r"^(\d*)d(\d+)([+-]\d+)?$")
COMMANDS = b"Accepted commands: /roll, /rolldm, /quit, /exit\n"

HEADER = """
  ██████  ▒█████   ▄████▄  ▀██ ▄█▀▓█████▄▄▄█████▓     ▓█████▄   ██ ▄████▄ ▓█████
▒██    ▒ ▒██▒  ██▒▒██▀ ▀█   ██▄█▒ ▓█   ▀▓  ██▒ ▓▒     ▒██▀ ██▌▒▓██▒██▀ ▀█ ▓█   ▀
░ ▓██▄   ▒██░  ██▒▒▓█    ▄ ▓███▄░ ▒███  ▒ ▓██░ ▒░     ░██   █▌░▒██▒▓█    ▄▒███  
  ▒   ██▒▒██   ██░▒▓▓▄ ▄██ ▓██ █▄ ▒▓█  ▄░ ▓██▓ ░     ▒░▓█▄   ▌ ░██▒▓▓▄ ▄██▒▓█  ▄
▒██████▒▒░ ████▓▒░▒ ▓███▀  ▒██▒ █▄░▒████  ▒██▒ ░     ░░▒████▓  ░██▒ ▓███▀ ░▒████
▒ ▒▓▒ ▒ ░░ ▒░▒░▒░ ░ ░▒ ▒   ▒ ▒▒ ▓▒░░ ▒░   ▒ ░░       ░ ▒▒▓  ▒  ░▓ ░ ░▒ ▒  ░░ ▒░ 
░ ░▒  ░    ░ ▒ ▒░   ░  ▒   ░ ░▒ ▒░ ░ ░      ░          ░ ▒  ▒   ▒   ░  ▒   ░ ░  
░  ░  ░  ░ ░ ░ ▒  ░        ░ ░░ ░    ░    ░ ░          ░ ░  ░   ▒ ░          ░  
      ░      ░ ░  ░ ░      ░  ░      ░                   ░      ░ ░ ░        ░  
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


class Server:
    def __init__(self, name, host, port, password):
        self.name = name
        self.host = host
        self.port = port
        self.password = password
        self.server = None
        self.running = True
        self.players = {}
        self.names = {}

    def _intro_client(self):
        return "client intro"

    def _intro_server(self):
        i = SERVER_INTROS[random.randint(1, len(SERVER_INTROS)-1)]
        return f"SOCKET DICE is listening for {i} on {self.host}:{self.port}"

    def set_name(self, addr, name):
        if addr in self.players:
            logging.info(f"{addr} already exists")
            return
        name = " ".join(name)
        n = re.sub(r"[^A-Za-z0-9 ]+", "", name)
        if n in self.names:
            logging.info(f"{name} already exists")
            return
        self.players[addr] = n
        self.names[n] = addr
        logging.info(f"Added player {n} from {addr}")

    def pname(self, addr):
        if addr in self.players:
            return self.players[addr]
        else:
            return "UNKNOWN PLAYER"

    def roll(self, input):
        if not input or len(input) == 0:
            result = [random.randint(1, 20), ]
            return result
        results = []
        for i in input:
            match = ROLL_PATTERN.match(i.strip())
            if not match:
                logging.info(f"Unknown roll format: {i}")
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

    def client_handler(self, conn, addr):
        logging.info(f"{addr} has connected to the adventure")
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
                    self.set_name(addr, msg)
                elif cmd == "/rolldm":
                    roll = self.rollstr(msg)
                    logging.info(f"[TO DM], {self.pname} rolls {roll}")
                elif cmd == "/roll":
                    roll = self.rollstr(msg)
                    conn.sendall(f"{self.pname(addr)} rolls {roll}\n".encode("utf-8"))
                else:
                    conn.sendall(COMMANDS)
        except ConnectionResetError:
            logging.info(f"{addr} has rage quit")
        finally:
            conn.close()
            logging.info(f"{addr} has gone back to reality")

    def __call__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        logging.info(self._intro_server())
        try:
            while self.running:
                conn, addr = self.server.accept()
                thread = threading.Thread(target=self.client_handler, args=(conn, addr))
                thread.start()
                logging.info(f"SOCKET DICE connections: {threading.active_count() - 1}")
        except KeyboardInterrupt:
            logging.info("\nSOCKET DICE has stopped")
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
