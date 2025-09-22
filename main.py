#!/usr/bin/env python3

import os
import sys
import argparse
from server import DiceServer


if __name__ == "__main__":
    cfg = {
        "host": os.getenv("DICEHOST", "0.0.0.0"),
        "port": os.getenv("DICEPORT", 5001),
        "password": os.getenv("DICEPASS", ""),
        "name": os.getenv("DICENAME", "Socket Dice Game"),
        "log": os.getenv("DICELOG", None),
    }
    parser = argparse.ArgumentParser()
    for k, v in cfg.items():
        parser.add_argument(f"--{k}", default=v)
    parser.add_argument("-r", "--reset", action="store_true", default=False, help="Reset the database and overwrite the log")
    args = parser.parse_args()
    try:
        port = int(args.port)
    except (ValueError, TypeError):
        print(f"Unknown port value: {args.port}")
        sys.exit(1)
    try:
        server = DiceServer(
            name=args.name,
            host=args.host,
            port=port,
            password=args.password,
            reset=args.reset)
        server()
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
