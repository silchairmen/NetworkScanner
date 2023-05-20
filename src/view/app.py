import socket
from flask import Flask, render_template, request, redirect, url_for, jsonify
from src.core.NetScan import NetScan
import ipaddress

app = Flask(__name__)
app.config['SERVER_NAME'] = 'localhost:5000'

global scan_hosts


#index
@app.route('/')
def index():
    return render_template('index.html', scan_hosts={}, ip=socket.gethostbyname(socket.gethostname()))


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
    ip = request.form["host"]

    #특정포트
    try:
        port = request.form['port']
        service = request.form['service']
    except Exception as e:
        pass

    # if port:
    #     ns = NetScan(ip, 32, [port])
    #     ns.portScan()

    default_ports = [20,21,22,23,25,80,443,3306,1221,1280]

    ns = NetScan(ip, 32, default_ports)
    scan_ports = ns.portScan(ip)

    return jsonify(scan_ports)

@app.route('/attack',methods=['POST'])
def attack():
    pass

if __name__ == '__main__':
    app.run(debug=True)
