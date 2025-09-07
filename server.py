import re
import random
import socket
import threading
from db import DB

ROLL_PATTERN = re.compile(r"^(\d*)d(\d+)([+-]\d+)?$")

client_name = "name"
client_addr = "addr"
client_conn = "conn"
client_unknown = "unknown"
dicelogger = "dicelogger"

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

class DiceServer:
    def __init__(self, name, host, port, password, logger, name_size=32, max_rolls=8):
        self.name = strip(name)
        self.host = host
        self.port = port
        self.password = password
        self.running = True
        self.clients= {}
        self.name_size = name_size
        self.max_rolls = max_rolls
        self.lock = threading.Lock()
        self.commands = {
                "/roll": self.cmd_roll,
                "/dm": self.cmd_rolldm,
                "/name": self.cmd_name,
        }
        self.logger = logger
        self.db = DB(self.name.replace(" ", "_").lower(), self.logger)

    def help(self):
        return f"Accepted commands: {" ".join([str(i) for i in self.commands])}".encode("utf-8")

    def logger(self, player: str=client_unknown, key: str = "rolls", value: str = ""):
        self.db.write(player, key, value)
        msg = f"{self.client_name(player)} {key}: {value}"
        self.logger.dice(msg)
        return msg
    
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
                    self.logger.info(f"broadcast error for {i}")
                    pass

    def cmd_name(self, key, name):
        new_name = " ".join(name)
        new_name = strip(new_name)[:self.name_size]
        if new_name == name:
            return
        old_name = self.clients[key][client_name]
        self.logger.info(f"{key} has changed their name from {old_name} to {new_name}")
        self.clients[key][client_name] = new_name

    def roll(self, msg):
        if not msg or len(msg) == 0:
            result = [random.randint(1, 20), ]
            return result
        results = []
        for i in msg:
            match = ROLL_PATTERN.match(i.strip())
            if not match:
                self.logger.info(f"Unknown roll format: {i}")
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

        return results[:self.max_rolls]

    def client_name(self, key):
        return self.clients.get([key], {}).get(client_name, client_unknown)
    
    def rollstr(self, msg):
        r = self.roll(msg)
        return ",".join(str(i) for i in r)
    
    def cmd_roll(self, key, msg):
        r = self.rollstr(msg)
        m = self.logger.info(self.client_name(key), "rolls", m)
        self.broadcast(m)
        return True

    def cmd_rolldm(self, key, msg):
        r = self.rollstr(msg)
        m = self.logger.info(self.client_name[key], "dm", r)
        self.clients[key][client_conn].sendall(m + b"\n")
   
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
        self.logger.info(f"Added client from {addr}")

    def cmd_exit(self, key, msg):
        self.clients[key][client_conn].sendall(b"Farewell\n")
        return False

    def client_handler(self, conn, addr):
        self.logger.info(f"{addr} has connected to the adventure")
        with self.lock:
            self.client_add(conn, addr)
        conn.sendall(b"Welcome to SOCKET DICE\n")
        conn.sendall(self.help())
        try:
            while True:
                data = conn.recv(1024).strip()
                if not data:
                    continue

                full_message = data.decode("utf-8").lower()
                m = full_message.split()
                if not m or len(m) == 0:
                    continue

                func = self.commands.get(m[0])
                msg = m[1:]
                key = self.client_key(addr)

                if func:
                    func(key, msg)
                else:
                    conn.sendall(self.help())
        except ConnectionResetError:
            self.logger.info(f"{addr} has rage quit")
        finally:
            with self.lock:
                if conn in self.clients:
                    self.clients.pop(conn, None)
            conn.close()
            self.logger.info(f"{addr} has gone back to reality")

    def __call__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        print(HEADER)
        self.logger.info(self._intro_server())
        try:
            while self.running:
                conn, addr = self.server.accept()
                thread = threading.Thread(target=self.client_handler, args=(conn, addr))
                thread.start()
                self.logger.info(f"SOCKET DICE connections: {threading.active_count() - 1}")
        except KeyboardInterrupt:
            self.logger.info("\nSOCKET DICE has stopped")
        finally:
            self.server.close()
            return False


