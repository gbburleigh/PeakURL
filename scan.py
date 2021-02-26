#!/usr/bin/env python
import os, sys, time, json, tempfile, subprocess, stat
from rich.console import Console
from urllib.parse import urlparse # obtained from StackOverflow to parse url
import dns
import dns.resolver as resolvers
from util import *

class Scanner():
    def __init__(self):
        self.console = Console()
        self.console.log('Starting scanner') 
        try:
            if sys.argv[1].find('.txt') != -1 :
                with open(sys.argv[1], 'r') as f: 
                    self.targets = [target for target in str(f.read()).split('\n')]
                    f.close()
            else:
                self.console.log('[!] Invalid input type, please use .txt')
                self.exit()
        except IndexError:
            self.console.log('[!] Invalid output path, use python3 scan.py <hosts> <output>')
            self.exit()
        try:
            if sys.argv[2].find('.json') != -1:
                self.output_file = sys.argv[2]
                if os.path.exists(self.output_file):
                    self.console.log('Found JSON obj of same name, overwriting...')
                else:
                    subprocess.call(["touch", self.output_file])
                    self.console.log('Created new JSON obj')
            else:
                self.console.log('[!] Invalid output type, please use .json')
                self.exit()
        except IndexError:
            self.console('[!] Invalid output path, use python3 scan.py <hosts> <output>')
            self.exit()
        self.console.log('Got {} targets, beginning scans...'.format(len(self.targets)))
        NULL = open(os.devnull, 'w')
        self.null = NULL
        self.domains = {}
        self.resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", \
        "9.9.9.9", "64.6.65.6", "91.239.100.100", "185.228.168.168", \
        "77.88.8.7", "156.154.70.1", "198.101.242.72", "176.103.130.130"]

    def scan_ipv4(self, domain):
        self.domains[domain]["ipv4_addresses"] = []
        resolver = resolvers.Resolver()
        resolver.nameservers = self.resolvers
        answer = resolver.resolve(domain, 'A')
        for a in answer:
            if str(a) not in self.domains[domain]['ipv4_addresses']:
                self.domains[domain]['ipv4_addresses'].append(str(a))

    def scan_ipv6(self, domain):
        self.domains[domain]["ipv6_addresses"] = []
        resolver = resolvers.Resolver()
        resolver.nameservers = self.resolvers
        try:
            answer = resolver.resolve(domain, 'AAAA')
        except dns.resolver.NoAnswer:
            answer = []
        for a in answer:
            if str(a) not in self.domains[domain]['ipv6_addresses']:
                self.domains[domain]['ipv6_addresses'].append(str(a))
        
    def scan_server_type(self, domain):
        import http.client as _http_
        conn = _http_.HTTPConnection(domain)
        conn.request('GET', '/')
        res = conn.getresponse()
        headers = res.getheaders()
        found = False
        hsts_found = False
        for tup in headers:
            if tup[0] == 'Server':
                self.domains[domain]['http_server'] = tup[1]
                found = True
                #break
            elif tup[0] ==  'Strict-Transport-Security':
                self.domains[domain]['hsts'] = True
                hsts_found = True
        
        if found is False:
            self.domains[domain]['http_server'] = None

        if hsts_found is False:
            self.domains[domain]['hsts'] = False

    def scan_insecure_http(self, domain):
        import http.client as _http_
        failures = 0
        conn = _http_.HTTPConnection(domain, port=80, timeout=3)
        conn.request('GET', '/')
        got_response = False
        try:
            res = conn.getresponse()
            got_response = True
        except _http_.ResponseNotReady:
            pass
        self.domains[domain]['insecure_http'] = got_response

    def scan_for_https(self, domain):
        #FIXME
        import http.client as _http_
        conn = _http_.HTTPConnection(domain)
        conn.request('GET', '/')
        res = conn.getresponse()
        status = res.status
        if int(status) > 300:
            pass

    def scan_tls(self, domain):
        #nmap --script ssl-enum-ciphers -p 443 northwestern.edu
        from subprocess import STDOUT, PIPE
        self.domains[domain]['tls_versions'] = []
        scan_output = subprocess.check_output(['nmap', '--script', 'ssl-enum-ciphers',\
            '-p', '443', domain], stderr=STDOUT).decode('utf-8')
        if scan_output.find('TLSv1.0') != -1:
            self.domains[domain]['tls_versions'].append('TLSv1.0')
        if scan_output.find('TLSv1.1') != -1:
            self.domains[domain]['tls_versions'].append('TLSv1.1')  
        if scan_output.find('TLSv1.2') != -1:
            self.domains[domain]['tls_versions'].append('TLSv1.2')
        # if scan_output.find('TLSv1.3') != -1:
        #     self.domains[domain]['tls_versions'].append('TLSv1.3')

    def scan_geo_location(self, domain):
        pass
    
    def scan_hsts(self, domain):
        pass

    def scan_rdns(self, domain):
        import dns.reversename as rev
        resolver = resolvers.Resolver()
        resolver.nameservers = self.resolvers
        self.domains[domain]['rdns_names'] = []
        for address in self.domains[domain]['ipv4_addresses']:
            queryname = rev.from_address(address)
            try:
                answer = resolver.resolve(queryname, 'PTR')
            except dns.resolver.NXDOMAIN:
                answer = []
            for ans in answer:
                self.domains[domain]['rdns_names'].append(str(ans))

    def scan_root_ca(self, domain):
        from subprocess import Popen, PIPE, STDOUT
        p = subprocess.Popen(['openssl', 's_client', '-tls1_3',\
            '-connect', domain + ':443'], stdout=PIPE, stdin=PIPE, stderr=self.null)
        result = p.communicate(input=b'Q\r')[0].decode('utf-8')
        if result.find('TLSv1.3') != -1:
            self.domains[domain]['tls_versions'].append('TLSv1.3')
        p.terminate()
        found = False
        try:
            self.domains[domain]['root_ca'] = result.split('i:O = ')[1].split(',')[0]
            found = True
        except IndexError:
            self.domains[domain]['root_ca'] = None

        if found is False:
            self.domains[domain]['root_ca'] = 'Not Found'

    def measure_rtt(self, domain):
        from subprocess import PIPE, Popen, STDOUT
        rtts = []
        for address in self.domains[domain]['ipv4_addresses']:
            res = subprocess.check_output(['sh', '-c', \
                "time echo -e '\x1dclose\x0d' | telnet {} 443".\
                    format(address)],stderr=STDOUT).decode('utf-8')
            for item in res.split('closed.\n')[1].split('\n'):
                if item == '':
                    continue
                else:
                    try:
                        rtt = item.split('.')[1].split('s')[0]
                        rtts.append(rtt)
                    except IndexError:
                        continue
        self.domains[domain]['rtt_range'] = [int(min(rtts)), int(max(rtts))]
            
    def format_json(self):
        pass

    def __str__(self):
        self.console.log('Dumping JSON...')
        return json.dumps(self.domains, indent=2)

    def exit(self):
        self.console.log('Exiting...')
        self.null.close()
        sys.exit()

    def printProgressBar (self, iteration, total, prefix = '', suffix = '', decimals = 1, length = 50, fill = '█', printEnd = "\r"):
        percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r          {prefix}|{bar}| {percent}% {suffix}', end = printEnd)
        if iteration == total: 
            print()

    def write_json(self):
        with open(self.output_file, 'w') as f:
            f.write(json.dumps(self.domains))
        f.close()
        self.console.log("Saved scan logs to '{}'".format(self.output_file))
        s = self.__str__()
        #self.console.log(self.domains)

    def run(self):
        i = 0
        self.printProgressBar(i, len(self.targets))
        for domain in self.targets:
            self.domains[domain] = {}
            self.domains[domain]["scan_time"] = time.time()
            self.scan_ipv4(domain)
            self.scan_ipv6(domain)
            self.scan_server_type(domain)
            self.scan_insecure_http(domain)
            self.scan_tls(domain)
            self.scan_root_ca(domain)
            self.scan_rdns(domain)
            self.measure_rtt(domain)
            i += 1
            self.printProgressBar(i, len(self.targets))
        self.write_json()
        self.exit()

if __name__ == "__main__":
    s = Scanner()
    s.run()
