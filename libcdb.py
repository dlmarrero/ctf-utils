#!/usr/bin/env python
import subprocess
import sys
import os
import re
from pwn import log


LIBCDB_DIR = '/home/dmo/ctf/utils/libc-database'


def main():
    libc_id = find_libc(*sys.argv[1:])
    log.info(libc_id)

    separator()

    offsets = dump_libc(libc_id, sys.argv[1])
    offsets.update(dump_libc(libc_id))
    
    for sym, addr in offsets.items():
        log.info('%s = %s' % (sym, hex(addr)))

    separator()

    print_oneg_results(libc_id)


def get_offsets(symbol, addr, libc_id=None, run_oneg=False):
    if not libc_id:
        libc_id = find_libc(symbol, hex(addr))
    
    offsets = dump_libc(libc_id, symbol)
    offsets.update(dump_libc(libc_id))

    libc_base = addr - offsets[symbol]
    addrs = {'base': libc_base}

    for symbol in offsets.keys():
        addrs[symbol] = libc_base + offsets[symbol]

    if run_oneg:
        log.warning('Fetching one_gadget results...')
        print_oneg_results(libc_id)

    return addrs


def print_oneg_results(libc_id):
    oneg_results = run_one_gadget(libc_id)
    for res in oneg_results:
        lines = res.split('\n')
        log.info(lines[0])
        for l in lines[1:]:
            print('    %s' % l)
        print('')


def find_libc(*args):
    find_argv = [os.path.join(LIBCDB_DIR, 'find')] + list(args)
    proc = subprocess.Popen(find_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    matches = proc.stdout.readlines()

    if not matches:
        log.warning('No matches found')
        exit(1)

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

    proc = subprocess.Popen(dump_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    offsets = {}
    for line in proc.stdout.readlines():
        l = line.decode()
        symbol, addr = l.split(' = ')
        offsets[symbol.replace('offset_', '')] = int(addr, 16)

    return offsets


def run_one_gadget(libc_id):
    oneg_argv = ['one_gadget', os.path.join(LIBCDB_DIR, 'db', libc_id + '.so')]
    proc = subprocess.Popen(oneg_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    results = proc.stdout.read().split('\n\n')
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

