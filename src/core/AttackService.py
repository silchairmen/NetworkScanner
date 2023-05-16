import getpass
import telnetlib

class AttackService:
    def __init__(self):
        pass

    def sshScan(self):
        pass

    def telnetScan(self):
        # HOST = "localhost"
        HOST = input("input host : ")
        user = input("Enter your remote account: ")
        password = getpass.getpass()

        tn = telnetlib.Telnet(HOST)

        tn.read_until(b"login: ")
        tn.write(user.encode('ascii') + b"\n")
        if password:
            tn.read_until(b"Password: ")
            tn.write(password.encode('ascii') + b"\n")

        tn.write(b"ls\n")
        tn.write(b"exit\n")

        print(tn.read_all().decode('ascii'))

    def ftpLfi(self):
        pass

    def ftpScan(self):
        pass