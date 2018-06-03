from os import listdir
from os.path import isfile, join
import re
from pprint import pprint

logdir = 'logs'

hostnames = []
with open('hostnames') as f:
    for line in f:
        if not line.startswith('#'):
            host = line.split()
            hostnames.append(host[0])

mac_list = []
with open('mac-addresses') as f:
    for line in f:
        if not line.startswith('#'):
            mac = line.split()
            mac_list.append(mac[0])

notifications = [ # total 589k messages
    'ddns-scripts-myddns: (Running|Update) ', # over 5k messages
    'dnsmasq\[1\d+\]: [cDeInrsu]', # over 9k messages
    'dnsmasq-dhcp\[1\d+\]: (DHCP|Ignoring|read /)', # over 29k messages

    'dropbear\[\d+\]: [BCEP]', # all 3704 messages
    #'dropbear\[\d+\]: Bad password attempt for \'root\' from 192.168.2.\d+:\d+',
    #'dropbear\[\d+\]: Child connection from ', #child connection ip dict
    #'dropbear\[\d+\]: Early exit: Failed socket address: Transport endpoint is not connected',
    #'dropbear\[\d+\]: Early exit: Terminated by signal',
    #'dropbear\[\d+\]: Exit \(root\): Disconnect received',
    #'dropbear\[\d+\]: Exit \(root\): Exited normally',
    #'dropbear\[\d+\]: Exit before auth \(user \'root\', \d fails\): Disconnect received',
    #'dropbear\[\d+\]: Exit before auth \(user \'root\', 0 fails\): Exited normally',
    #'dropbear\[\d+\]: Exit before auth: Incompatible remote version \'SSH-1.5-Nmap-SSH1-Hostkey\'',
    #'dropbear\[\d+\]: Exit before auth: Error reading: Connection reset by peer',
    #'dropbear\[\d+\]: Exit before auth: Exited normally',
    #'dropbear\[\d+\]: Exit before auth: Timeout before auth',
    #'dropbear\[\d+\]: Password auth succeeded for \'root\' from \d+\.\d+\.\d+\.\d+:\d+',
    #'dropbear\[\d+\]: Pubkey auth succeeded for \'root\' with key md5 ',

    'firewall: Reloading firewall due to ifup of (vpn|wan)', # 2 types
    'hostapd: wlan0: STA [034789abde]', # almost 150k messages
    'kernel: \[\s*\d+.\d+\] [abeInrU]', # over 4.5k message
    'logread\[711\]: Logread connected to 192.168.2.227:514',

    'netifd: wan \(\d+\): (Lease|Sending|udhcpc) ', # over 226k messages
    'netifd: (Interface|Network) ', # 1607 messages

    'odhcpd\[7\d+\]: DHCPV6 (CONFIRM|REBIND|RELEASE|REQUEST|SOLICIT) IA_NA from ', # about 9k messages

    'openvpn\(sample_client\)\[83\d\]: [ATVDCRSPOIFde/\[]', # over 59k messages
    'openvpn\(server\)\[8\d+\]: [hmwMORT12689]', # over 90k messages

    'pppd\[108\d\]: [NSCL]', # 5 types
    'procd: - shutdown -',
    ]

ignore = []
for name in hostnames:
    for phrase in notifications:
        ignore.append(name + ' ' + phrase)

def read_log(files: list) -> list:
    result = []
    for file in files:
        with open(file) as f:
            for line in f:
                for phrase in ignore:
                    match = re.search(phrase, line)
                    if match:
                        break
                else:
                    result.append(line.rstrip())
    print(len(result))
    return result

def child_connection_ip_dict(files: list) -> dict:
    ip = {}
    regex = 'dropbear\[\d+\]: Child connection from (\d+\.\d+\.\d+\.\d+):(\d+)'
    for file in files:
        with open(file) as f:
            for line in f:
                match = re.search(regex, line.rstrip())
                if match:
                    ip.setdefault(match.group(1), [])
                    ip[match.group(1)].append(match.group(2))
    return ip

def mac_addresses(files: list) -> set:
    result = set()
    regex = 'hostapd: wlan0: STA (([0-9a-f]{2}:){5}[0-9a-f]{2}) '
    for file in files:
        with open(file) as f:
            for line in f:
                match = re.search(regex, line)
                if match and match.group(1) not in mac_list:
                    result.add(match.group(1))
    macs = list(result)
    macs.sort()
    return macs                

if __name__ == '__main__':
    logfiles = [join(logdir, f) for f in listdir(logdir) if isfile(join(logdir, f))]
    logfiles.sort()
    for line in read_log(logfiles):
        print(line)
    print('MAC not in known list', mac_addresses(logfiles))
    pprint(child_connection_ip_dict(logfiles))
