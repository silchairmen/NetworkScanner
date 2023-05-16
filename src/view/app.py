from flask import Flask, jsonify, render_template, request
from src.core.NetScan import NetScan
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True


@app.route('/scan', methods=['POST','GET'])
def scan_hosts():
    if request.method == 'GET':
        return render_template('scan.html')

    elif request.method == 'POST':

        net_addr = request.form['net_addr']
        subnetmask = request.form['subnetmask']
        target_port = 80  # 대상 포트

        scanner = NetScan(net_addr, subnetmask, target_port)
        results = scanner.avail_host_scan()

        # 결과를 JSON 형식으로 응답
        return jsonify(results=results)

def run_web(ip, port):
    app.run(host=ip, port=port)