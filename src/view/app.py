import socket
from flask import Flask, render_template, request, redirect, url_for, jsonify
from src.core.NetScan import NetScan
import ipaddress
from src.core.CustomFunc import *
from src.core.AttackService import *

app = Flask(__name__)
app.config['SERVER_NAME'] = 'localhost:5000'

scan_hosts = {}


#index
@app.route('/')
def index():
    global scan_hosts
    return render_template('index.html', scan_hosts=scan_hosts, ip=socket.gethostbyname(socket.gethostname()))


#scan데이터를 처리하는 곳
@app.route('/scan', methods=['POST'])
def scan():
    #ajax로 post data 전송받음
    network = request.form['network']
    netmask = request.form['netmask']


    #백그라운드에서 hostscan 수행
    ns = NetScan(network, netmask, [])
    global scan_hosts
    scan_hosts = ns.hostScan()

    ip = socket.gethostbyname(socket.gethostname())
    return jsonify(scan_hosts=scan_hosts, ip=ip)  # JSON 응답으로 변경


#host들중에서 한개의 호스트를 골라 분석
@app.route('/host_details', methods=['GET'])
def host_details():
    host = request.args.get('host')
    network_address = host.split('/')[0]
    netmask = 32

    return render_template('host.html', host=network_address, netmask=netmask, scan_hosts=scan_hosts)



@app.route('/port_scan', methods=['POST'])
def portscan():
    startPort = 0
    endPort = 0
    service = ""
    ports = []

    ip = request.form["host"]


    #특정포트 파라미터 받기
    try:
        startPort = int(request.form['startPort'])
        endPort = int(request.form['endPort'])
        service = request.form['service']

        # 특정 포트 받으면 포트 리스트 생성
        for i in range(startPort, endPort + 1):
            ports.append(i)

        print("----------port scan-------------")
        p_print("시작 포트 : " + str(startPort))
        p_print("끝 포트 : " + str(endPort))
        p_print("서비스 : " + str(service))
        print("--------------------------------")

    except Exception as e:
        print("port scan도중 발생한 에러 app.py line:60"+str(e))


    if ports:
        serviceDict = {"JUST PORT SCAN":None,
                       "CHOOSE SERVICE":None,
                       "FTP":'21',
                       "SSH":'22',
                       "TELNET":'23',
                       "SMTP":None,
                       "HTTP":None,
                       "Mysql":None}

        ns = NetScan(ip, 32, ports)
        scan_ports = ns.portScan(ip, serviceDict[service.upper()]) #{ip : [ports]}

    else:
        #주요 포트 점검표
        default_ports = [20,21,22,23,25,80,443,3306]
        ns = NetScan(ip, 32, default_ports)
        scan_ports = ns.portScan(ip)

    return jsonify(scan_ports)


@app.route('/attackOptions', methods=['POST'])
def attackOptions():
    ip = ""
    port = ""
    action = ""

    try:
        ip = request.form['ip']
        port = request.form['port']
        action = request.form['action']

    except Exception as e:
        e_print("Error while get post data..")
        data = {'error':e}
        return jsonify(data)

    act = AttackService(ip)

    _action = action.lower()

    print (_action)

    if _action=="ftp annonymous scan":
        data = act.anonLogin(port)
    elif _action == "ftp login broute force":
        data = act.ftpBruteLogin(port)
    elif _action == "ssh login broute force":
        data = act.sshBruteLogin(port)
    elif _action == "telnet login broute force":
        data = act.telnetBruteLogin(port)
    else:
        data = {'error':'Not supported action'}

    print(data)

    return jsonify(data)



def run():
    app.run(debug=True)


if __name__ == '__main__':
    app.run(debug=True)
