#!/usr/bin/env python3
import subprocess
import sys
import os
import re
from pwn import log


LIBCDB_DIR = '/home/dmo/ctf/utils/libc-database'


def main():
    libc_id = find_libc(sys.argv[1:])
    log.info(libc_id)

    separator()

    symbol_offset = dump_libc(libc_id, sys.argv[1])
    other_offsets = dump_libc(libc_id)
    
    offsets = {**symbol_offset, **other_offsets}
    for sym, addr in offsets.items():
        addr = hex(int(addr, 16))
        log.info(f'{sym} = {addr}')

    separator()

    oneg_results = run_one_gadget(libc_id)
    for res in oneg_results:
        lines = res.split('\n')
        log.info(lines[0])
        for l in lines[1:]:
            print('    %s' % l)
        print('')


def find_libc(args: list):
    find_argv = [os.path.join(LIBCDB_DIR, 'find')] + args
    proc = subprocess.run(find_argv, capture_output=True)
    
    matches = [l.decode() for l in proc.stdout.splitlines()]

    if len(matches) > 1:
        selection = prompt_for_match(matches)
    else:
        selection = matches[0]

    lib_id = extract_id(selection)
    return lib_id


def dump_libc(libc_id, symbol=None):
    dump_argv = [os.path.join(LIBCDB_DIR, 'dump'), libc_id]
    if symbol:
        dump_argv.append(symbol)

    proc = subprocess.run(dump_argv, capture_output=True)
    
    offsets = {}
    for line in proc.stdout.splitlines():
        l = line.decode()
        symbol, addr = l.split(' = ')
        offsets[symbol.replace('offset_', '')] = addr

    return offsets


def run_one_gadget(libc_id):
    oneg_argv = ['one_gadget', os.path.join(LIBCDB_DIR, 'db', libc_id + '.so')]
    proc = subprocess.run(oneg_argv, capture_output=True)
    results = proc.stdout.decode().split('\n\n')
    return results


def prompt_for_match(matches):
    log.warning('SELECT LIBC VERSION')
    for i, m in enumerate(matches):
        log.info('%d: %s' % (i+1, m))

    sel = int(input('> '))
    print('')

    return matches[sel-1]


def extract_id(selection):
    p = re.compile('id (.*)\)')
    m = p.search(selection)
    return m.group(1)


def separator():
    print('-' * 0x20)


if __name__ == '__main__':
    main()

