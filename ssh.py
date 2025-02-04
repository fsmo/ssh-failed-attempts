#!/usr/bin/python3.6

import json
import re
import sys
import subprocess
from collections import Counter
from datetime import datetime

MC = 20

if len(sys.argv) > 1:
    try:
        MC = int(sys.argv[1])
    except:
        print('ERROR: Invalid value. Specify n to list the n most common attacks.')
        exit(1)

def persist_counter(c: Counter, filename: str):
    o = {k: v for k, v in sorted(dict(c).items(), key=lambda item: item[1])}
    with open(f'ssh-result/{filename}', 'w') as w:
        json.dump(obj=o, fp=w, indent=2)
    print(f'Dumped result to ssh-result/{filename}.')

def print_counter(c: Counter):
    ljust = 30
    for cc in c.most_common(MC):
        key, value = cc
        print(f'{str(key).ljust(ljust)} : {value:,}')
    print(f'{"TOTAL".ljust(ljust)} : {sum(c.values()):,}')

def read_line(line: str):
    match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)', line)
    if match:
        user, ip = match.groups()
        return ip, user, 1, datetime.utcnow()
    return None

class Processor:
    def __init__(self):
        self.oldest_date = datetime.utcnow()
        self.ip_counter = Counter()
        self.user_counter = Counter()
        self.joint_counter = Counter()
        self.attempts = 0

    def print(self):
        print('------- Attackers IPs and their username guesses (most common) -------')
        print_counter(self.joint_counter)
        print('\n------- Attackers IPs (most common) -------')
        print_counter(self.ip_counter)
        print('\n------- Attackers username guesses (most common) -------')
        print_counter(self.user_counter)

    def apply(self, line: str):
        o = read_line(line)
        if o is not None:
            ip, user, count, d = o
            self.attempts += count
            self.ip_counter[ip] += count
            self.user_counter[user] += count
            self.joint_counter[(ip, user)] += count

    def persist(self):
        persist_counter(self.joint_counter, 'ip_user.json')
        persist_counter(self.ip_counter, 'ip.json')
        persist_counter(self.user_counter, 'user.json')

def main():
    print('*******************************')
    print('** SSH ATTACKS COUNTER TOOL  **')
    print('*******************************')
    print('Reading logs from journalctl...')
    
    p = Processor()
    try:
        result = subprocess.run(['journalctl', '-u', 'ssh', '--no-pager'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            p.apply(line)
    except Exception as e:
        print(f'ERROR: Failed to read logs - {e}')
        exit(1)
    
    p.print()
    p.persist()

if __name__ == '__main__':
    main()

