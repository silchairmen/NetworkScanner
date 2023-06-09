import os
import platform
import ipaddress
import socket
import threading
from datetime import datetime
from src.core.AttackService import *

from src.core.CustomFunc import *
from queue import Queue
#인코딩
os.system('chcp 65001')

class NetScan:
    def __init__(self, netAddr, subnet, targetPorts):
        self.ipRange = list(ipaddress.ip_network(netAddr + '/' + str(subnet)))
        self.targetPorts = targetPorts

        #key : ip  | value : 스캔 시각
        self.availHostDict = {}

        #key : ip : value : [port, 스캔 시각]
        self.availPortDict = {}

        #자신의 ip 저장
        self.machineIp = socket.gethostbyname(socket.gethostname())
        p_print(f"Computer IP : {self.machineIp}")

        #자신의 ip는 탐색에서 제외
        try:
            self.ipRange.remove(self.machineIp)
        except Exception as e:
            pass

        #Windows, Linux os 판별
        self.osType = platform.system()


    #ICMP를 이용한 HostScan
    def hostScan(self):
        #병렬 처리를 위한 큐와 스레드 리스트 생성
        q = Queue()
        threads = []
        availHostLock = threading.Lock()

        def worker():
            while True:
                targetIp = q.get()
                if targetIp is None:
                    break

                if self.osType=="Windows":
                    scanWinHost(targetIp)
                else:
                    scanLinuxHost(targetIp)

                q.task_done()

        def scanLinuxHost(targetIp):
            alive = os.system("ping -c 1 " + str(targetIp) + "2>/dev/null")

            #응답이 있으면 호스트와 스캔 시각을 작성
            if alive == 0:
                timelog = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                with availHostLock:
                    self.availHostDict[str(targetIp)] = timelog


        def scanWinHost(targetIp):
            alive = os.system("ping -n 1 -w 1000 " + str(targetIp) + " > NUL")

            if alive == 0:
                timelog = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                with availHostLock:
                    self.availHostDict[str(targetIp)] = timelog



        #스레드 생성
        for i in range(30):
            t = threading.Thread(target=worker)
            t.setDaemon=True
            t.start()
            threads.append(t)

        #q 에 IP를 넣고 작업이 끝날 때까지 대기, 서브넷 마스크가 24일때는 처음과 끝을 빼줌
        if len(self.ipRange) == 256:
            for ip in self.ipRange[1:-1]:
                q.put(ip)
        else:
            for ip in self.ipRange:
                q.put(ip)

        q.join()

        #None값을 넣어 큐의 종료 시점을 알리고 thread가 끝날때까지 대기
        for i in range(30):
            q.put(None)
        for t in threads:
            t.join()
        p_print("Scan completed")
        return self.availHostDict



    #포트스캔
    def portScan(self, targetList=None, service=None):
        p_print(f"target = {self.ipRange} port is:"+targetList)
        socket.setdefaulttimeout(3)
        #portscan 핸들링 함수
        def worker():
            while True:
                targetIp = q.get()
                if targetIp is None:
                    break

                scan(targetIp)
                q.task_done()


        #portscan 실행 함수
        def scan(targetIp):
            atk = AttackService(targetIp)
            resPorts = []

            for port in self.targetPorts:
                p_print("Target port : "+str(port))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                port = int(port)
                res = sock.connect_ex((targetIp, port))
                if res == 0:
                    if service==None:
                        resPorts.append(port)

                    # 포트가 열려있으면 서비스 탐색
                    else:
                        if service=='20' or service=='21':
                            p_print("FTP 서비스 스캔 추가 요청 실행중...")
                            res = atk.ftpScan(port)
                        elif service=='22':
                            p_print("SSH 서비스 스캔 추가 요청 실행중...")
                            res = atk.sshScan(port)
                        elif service=='23':
                            res = atk.telnetScan(port)
                            p_print("FTP 서비스 스캔 추가 요청 실행중...")
                        elif service=='80' or service=='443':
                            p_print("HTTP/S 서비스 스캔 추가 요청 실행중...")
                            res = atk.httpScan(port)

                        #사용자가 서비스를 선택했고 결과가 나온경우
                        if res == True:
                            resPorts.append(port)

                    #@todo 포트에 따른 스캐너 추가 구현

                sock.close()

            with availHostLock:
                self.availPortDict[targetIp] = resPorts
        #target List 핸들링
        #1.단일 ip로 주어지는 경우 리스트로 변환
        #2.리스트로 주어지는 경우 pass
        #3.아무것도 없는경우 hostdict 검사

        if targetList is None:
            if self.availHostDict != {}:
                targetList = list(self.availHostDict.keys())

            else:
                e_print("Error : No avail Host")
                return 0

        elif targetList is not None:
            if type(targetList)==str:
                targetList = [targetList]

            elif type(targetList)==list:
                pass

            else:
                e_print("Error : No avail Host")
                return 0


        q = Queue()
        threads = []
        availHostLock = threading.Lock()

        for i in range(30):
            t = threading.Thread(target=worker)
            t.setDaemon=True
            t.start()
            threads.append(t)

        for host in targetList:
            q.put(host)

        q.join()

        for i in range(30):
            q.put(None)
        for t in threads:
            t.join()

        e_print(self.availPortDict)
        return self.availPortDict


if __name__=="__main__":
    ns = NetScan("192.168.150.0","24",[1280,1221,1234,1222,1223])

    data1 = ns.hostScan()
    data2 = ns.portScan("127.0.0.1")
    print(data2)



