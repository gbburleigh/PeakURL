#!/usr/bin/env python
import os, sys, texttable, json, tabulate
from util import *

try:
    inp = sys.argv[1]
    out = sys.argv[2]
except IndexError:
    prRed('[!] Invalid args, please use python3 report.py <input> <output>')
    sys.exit()

if inp.find('.json') == -1: 
    prRed('[!] Invalid input file type, please use .json')
    sys.exit()

if out.find('.txt') == -1:
    prRed('[!] Invalid output file type, please use .txt')
    sys.exit()

try:
    with open(str(inp)) as f:
        df = json.load(f)
        prGreen('Loaded json successfully')
        l = []
        rtts = []
        root_ca = {}
        servers = {}
        insecure_allowed = 0
        ipv6_supported = 0
        for d in df:
            prYellow('\n' + d)
            table = tabulate.tabulate(df[d].items(), tablefmt='grid')
            l.append(table)
            rtts.append(df[d]['rtt_range'])
            if df[d]['root_ca'] in root_ca:
                root_ca[df[d]['root_ca']] += 1
            else:
                root_ca[df[d]['root_ca']] = 1

            if df[d]['http_server'] in servers:
                servers[df[d]['http_server']] += 1
            else:
                servers[df[d]['http_server']] = 1

            if df[d]['insecure_http'] is True:
                insecure_allowed += 1

            if len(df[d]['ipv6_addresses']) > 0:
                ipv6_supported += 1

            prYellow(table)
        #print(tabulate.tabulate(l, tablefmt='grid'))
        #print(root_ca)
        #print(sorted(rtts))
        prGreen(tabulate.tabulate(sorted(rtts), tablefmt='grid'))
        prRed(tabulate.tabulate(root_ca, tablefmt='grid'))
        prCyan(tabulate.tabulate(sorted(servers)))
        prRed(tabulate.tabulate())
except FileNotFoundError:
    prRed("[!] File doesn't exist")
    sys.exit()



