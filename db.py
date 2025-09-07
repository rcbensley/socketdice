import sqlite3
import threading

keys = {
        "rolls": True,
        "dm": True,
        "msg": True,
        "server": True,
        "player": True
}

class DB:
    def __init__(self, name, logger):
        self.name = f"{name}.sqlite"
        self.logger = logger
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(self.name)
        self.cur = self.conn.cursor()
        self.create()


    def query(self, sql):
        with self.lock:
            self.conn.execute(sql)
            self.conn.commit()

    def create(self):
        table = f"""
        CREATE TABLE IF NOT EXISTS "dicelogger" (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dt DATETIME DEFAULT CURRENT_TIMESAMP,
        player TEXT NOT NULL default "client_unknown",
        key TEXT NOT NULL NOT NULL DEFAULT "rolls",
        value TEXT NOT NULL
        );
        """
        idx = """CREATE INDEX IF NOT EXISTS idx_dt ON dicelogger(dt)"""
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
            self.conn.execute(table)
            self.conn.execute(idx)
            self.conn.commit()

    def write(self, player: dict, key: str, value: str):
        sql = f"INSERT INTO {dicelogger} (player, key, value) VALUES ({player}, {key}, {value});"
        self.query(sql)
