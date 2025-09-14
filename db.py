import sqlite3

keys = {
        "rolls": True,
        "dm": True,
        "msg": True,
        "server": True,
        "player": True
}

class DB:
    def __init__(self, name, logger, lock, overwrite=False):
        self.name = f"{name}.sqlite"
        self.logger = logger
        self.lock = lock
        self.conn = sqlite3.connect(self.name, check_same_thread=False)
        self.create(overwrite)


    def query(self, sql):
        with self.lock:
            self.conn.execute(sql)
            self.conn.commit()

    def create(self, overwrite=False):
        table = """
        CREATE TABLE IF NOT EXISTS "dicelogger" (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dt DATETIME DEFAULT CURRENT_TIMESAMP,
        client TEXT NOT NULL,
        channel TEXT NOT NULL,
        msg TEXT NOT NULL
        );
        """
        idx = """CREATE INDEX IF NOT EXISTS idx_dt ON dicelogger(dt)"""
        with self.lock:
            if overwrite:
                self.conn.execute("DROP TABLE IF EXISTS 'dicelogger'")
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")
            self.conn.execute(table)
            self.conn.execute(idx)
            self.conn.commit()

    def write(self, client, channel, msg):
        sql = f"INSERT INTO dicelogger (client, channel, msg) VALUES ('{client}', '{channel}', '{msg}');"
        self.query(sql)
