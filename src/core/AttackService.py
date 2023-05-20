import getpass
import telnetlib
from paramiko import SSHClient, AutoAddPolicy
import paramiko
import ftplib

class AttackService:
    def __init__(self, targetIp):
        self.targetIp = targetIp

    def sshScan(self, port=None) -> bool:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        try:
            if port==None:
                id = ssh.connect(self.targetIp, port=22)
                print(id)
                ssh.close()
            else:
                ssh.connect(self.targetIp, port=port, timeout=5)
                ssh.close()
            return True
        except Exception as e:
            if "Authentication" in str(e):
                return True
            else:
                return False

    def telnetScan(self, port=None) -> bool:
        isTelnet = False

        if port==None:
            tn = telnetlib.Telnet(self.targetIp)
        else:
            tn = telnetlib.Telnet(self.targetIp, port=port)

        response = tn.read_until(b"login").decode('ascii')

        if "login" in response:
            isTelnet = True

        return isTelnet

    def ftpLfi(self):
        pass

    def ftpScan(self, port=None) -> bool:
        try:
            ftp = ftplib.FTP()
            if port is not None:
                ftp.connect(self.targetIp, port, timeout=5)
            else:
                ftp.connect(self.targetIp, 21, timeout=5)
            return True
        except Exception as e:
            return False

    def anonLogin(self, port=None) -> bool:
        try:
            ftp = ftplib.FTP()

            if port==None:
                ftp.connect(self.targetIp, 21, timeout=5)
                ftp.login()
                ftp.quit()
            else:
                ftp.connect(self.targetIp, port, timeout=5)
                ftp.login()
                ftp.quit()
            return True
        except Exception as e:
            return False

if __name__=="__main__":
    a = AttackService("127.0.0.1")
    b = a.anonLogin(1221)
    print(b)