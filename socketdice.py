#!/usr/bin/env python3

import os
import re
import socket
import random
import argparse
import threading

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
    "the Bard to TPK...again",
    "your nat 20's! Nah just kidding, it's a 1 again",
    "to rig the DC for all charisma builds",
    "them to talk themselves outta this one",
    "the party to just opt for violence, again",
    "to be really cautious and careful in their decisions",
    "just meta it",
]

CLIENT_INTROS = [
]

class Server:
    def __init__(self, host, port, password):
       self.host = host
       self.port = port
       self.password = password
       self.server = None
       self.running = True
       self.players = {}

    def _intro_client(self):
        return "client intro"

    def _intro_server(self):
        i = SERVER_INTROS[random.randint(1,len(SERVER_INTROS-1))]
        return f"SOCKET DICE is listening for {i} on {self.host}:{self.port}"

    def roll(self, input):
        results = []
        if not input or len(input) == 0:
            results.append(random.randint(1,20))
            return results
        for i in input:
            match = dice_pattern.match(i.strip())
            if not match:
                print(f"Unknown roll format: i")
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

    def client_handler(self, conn, addr):
        print(f"{addr} has connected to the adventure")
        conn.sendall(b"Welcome to SOCKET DICE\n")
        conn.sendall(COMMANDS)
        try:
            while True:
                data = conn.recv(1024).strip()
                if not data:
                    break # Disconnect

                full_message = data.decode("utf-8").lower()
                m = full_message.spit()
                if not m or len(m) == 0:
                    continue

                if m[0] in ("/exit", "/quit"):
                    conn.sendall(b"Farewell\n")
                    break
                elif m[0] == "/rolldm":
                    roll = self.roll(message)
                    conn.sendall(f"You rolled a {roll}\n".encode("utf-8"))
                elif m[0] == "/roll":
                    roll = self.roll(message)
                    conn.sendall(f"You rolled a {roll}\n".encode("utf-8"))
                else:
                    conn.sendall(COMMANDS)
        except ConnectionResetError:
            print(f"{addr} has rage quit")
        finally:
            conn.close()
            print(f"{addr} has to go back to reality")


    def __call__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        print(self._intro_server)
        try:
          while self.running:
              print(HEADER)
              conn, addr = self.server.accept()
              thread = threading.Thread(target=self.client_handler, args=(conn, addr))
              thread.start()
              print(f"SOCKET DICE connections: {threading.active_count() - 1}")
        except KeyboardInterrupt:
            print("\nSOCKET DICE has stopped")
        finally:
            self.server.close()


if __name__ == "__main__":
    cfg = {
            "host": os.getenv("DICEHOST", "0.0.0.0"),
            "port": os.getenv("DICEPORT", 5001),
            "pass": os.getenv("DICEPASS", ""),
    }
    parser = argparse.ArgumentParser()
    for k, v in cfg.items():
        parser.add_argument(f"--{k}", default=v)
    args = parser.parse_args()

    server = Server(args.host, args.port, args.password)
    server()
