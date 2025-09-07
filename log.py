import re
import logging
import threading
from pathlib import Path

DICELOGGER_LEVEL = 25


def dicelevel(self, message, *args, **kwargs):
    if self.isEnabledFor(DICELOGGER_LEVEL):
        self._log(DICELOGGER_LEVEL, message, args, **kwargs)



class ServerLog:
    def __init__(self, path: str=None):
        logging.addLevelName(DICELOGGER_LEVEL, "DICELOGGER")
        self.logger = logging.getLogger("Socket Dice")
        self.logger.dice = dicelevel
        log_fmt = logging.Formatter(
                f"%(asctime)s {self.name}: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S")
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(log_fmt)
        if path:
            file_handler = logging.FileHandler(
                    path,
                    mode="a",
                    encoding="utf-8")
            file_handler.setFormatter(log_fmt)
            self.logger.addHandler(stream_handler)
            self.logger.addHandler(file_handler)


