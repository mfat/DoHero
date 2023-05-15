import sys
import socket
import json
import ssl
import http.client
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QTextEdit, QHBoxLayout, QComboBox, QGroupBox

class DNSTester(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.hostnameLabel = QLabel('Hostname:')
        self.hostnameEdit = QLineEdit()
        self.httpButton = QPushButton('Test DNS-over-HTTPS')
        self.tlsButton = QPushButton('Test DNS-over-TLS')
        self.resultLabel = QLabel()
        self.resultText = QTextEdit()
        self.resultText.setReadOnly(True)

        self.dnsTypeLabel = QLabel('DNS Server:')
        self.dnsTypeCombo = QComboBox()
        self.dnsTypeCombo.addItem('Cloudflare DNS (HTTPS)')
        self.dnsTypeCombo.addItem('Google DNS (HTTPS)')
        self.dnsTypeCombo.addItem('Quad9 DNS (HTTPS)')
        self.dnsTypeCombo.addItem('Custom DNS (HTTPS)')
        self.dnsTypeCombo.addItem('Custom DNS (TLS)')

        self.customDoHEdit = QLineEdit()
        self.customDoHEdit.setPlaceholderText('Enter custom DoH server URL')
        self.customDoHEdit.setEnabled(True)

        self.customDoTEdit = QLineEdit()
        self.customDoTEdit.setPlaceholderText('Enter custom DoT server hostname and port (e.g. dns.google:853)')
        self.customDoTEdit.setEnabled(True)

        self.dnsTypeCombo.currentIndexChanged.connect(self.onDnsTypeChanged)

        dnsTypeLayout = QHBoxLayout()
        dnsTypeLayout.addWidget(self.dnsTypeLabel)
        dnsTypeLayout.addWidget(self.dnsTypeCombo)

        customDoHLayout = QHBoxLayout()
        customDoHLayout.addWidget(self.customDoHEdit)

        customDoTLayout = QHBoxLayout()
        customDoTLayout.addWidget(self.customDoTEdit)

        customLayout = QVBoxLayout()
        customLayout.addLayout(customDoHLayout)
        customLayout.addLayout(customDoTLayout)

        customGroupBox = QGroupBox('Custom DNS')
        customGroupBox.setLayout(customLayout)
        customGroupBox.setEnabled(True)

        vbox = QVBoxLayout()
        vbox.addWidget(self.hostnameLabel)
        vbox.addWidget(self.hostnameEdit)
        vbox.addLayout(dnsTypeLayout)
        vbox.addWidget(customGroupBox)
        vbox.addWidget(self.httpButton)
        vbox.addWidget(self.tlsButton)
        vbox.addWidget(self.resultLabel)
        vbox.addWidget(self.resultText)

        self.setLayout(vbox)

        self.httpButton.clicked.connect(self.testDoH)
        self.tlsButton.clicked.connect(self.testDoT)

        self.setGeometry(300, 300, 400, 400)
        self.setWindowTitle('DNS Tester')
        self.show()

    def onDnsTypeChanged(self, index):
        if index == 3:
            self.customDoHEdit.setEnabled(True)
            self.customDoTEdit.setEnabled(False)
            self.customDoTEdit.clear()
            self.resultText.clear()
        elif index == 4:
            self.customDoHEdit.setEnabled(False)
            self.customDoTEdit.setEnabled(True)
            self.customDoHEdit.clear()
            self.resultText.clear()
        else:
            self.customDoHEdit.setEnabled(False)
            self.customDoTEdit.setEnabled(False)
            self.customDoHEdit.clear()
            self.customDoTEdit.clear()
            self.resultText.clear()

    def testDoH(self):
        self.resultText.clear()
        hostname = self.hostnameEdit.text()
        if not hostname:
            self.resultLabel.setText('Please enter a hostname')
            return

        dns_server = self.dnsTypeCombo.currentText()
        if dns_server == 'Cloudflare DNS (HTTPS)':
            server = 'cloudflare-dns.com'
            path = '/dns-query'
        elif dns_server == 'Google DNS (HTTPS)':
            server = 'dns.google'
            path = '/resolve'
        elif dns_server == 'Quad9 DNS (HTTPS)':
            server = 'dns9.quad9.net'
            path = '/dns-query'
        elif dns_server == 'Custom DNS (HTTPS)':
            server = self.customDoHEdit.text().strip('/')
            path = ''
        else:
            server_port = self.customDoTEdit.text().split(':')
            if len(server_port) != 2:
                self.resultText.append('Invalid custom DoT server format')
                return
            server = server_port[0]
            port = int(server_port[1])

        try:
            if path:
                conn = http.client.HTTPSConnection(server)
                url = f'https://{server}{path}?name={hostname}&type=A'
                conn.request('GET', url)
                response = conn.getresponse()
                response_text = response.read().decode('utf-8')
                response_json = json.loads(response_text)
            else:
                conn = http.client.HTTPSConnection(server, timeout=5)
                url = f'{server}?dns={hostname}'
                conn.request('GET', url)
                response = conn.getresponse()
                response_text = response.read().decode('utf-8')
                response_json = json.loads(response_text)['Answer']

            if 'Answer' in response_json:
                self.resultText.append(f'{server}: working')
            else:
                self.resultText.append(f'{server}: not working')
        except Exception as e:
            self.resultText.append(f'{server}: not working')

        self.resultLabel.setText('Results:')
        self.resultLabel.setStyleSheet('color: black; font-weight: bold;')

    def testDoT(self):
        self.resultText.clear()
        hostname = self.hostnameEdit.text()
        if not hostname:
            self.resultLabel.setText('Please enter a hostname')
            return

        dns_server = self.dnsTypeCombo.currentText()
        if dns_server == 'Cloudflare DNS (HTTPS)':
            self.resultText.append('DNS-over-TLS is not supported by Cloudflare DNS')
            return
        elif dns_server == 'Google DNS (HTTPS)':
            server = 'dns.google'
            port = 853
        elif dns_server == 'Quad9 DNS (HTTPS)':
            server = 'dns.quad9.net'
            port = 853
        elif dns_server == 'Custom DNS (TLS)':
            server_port = self.customDoTEdit.text().split(':')
            if len(server_port) != 2:
                self.resultText.append('Invalid custom DoT server format')
                return
            server = server_port[0]
            port = int(server_port[1])

        try:
            context = ssl.create_default_context()
            with socket.create_connection((server, port)) as sock:
                with context.wrap_socket(sock, server_hostname=server) as ssock:
                    query = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                    query += bytes([len(hostname)]) + hostname.encode()
                    query += b'\x00\x00\x01\x00\x01'
                    ssock.send(query)
                    response = ssock.recv(1024)
                    if response:
                        self.resultText.append(f'{server}:{port} working')
                    else:
                        self.resultText.append(f'{server}:{port} not working')
        except Exception as e:
            self.resultText.append(f'{server}:{port} not working')

        self.resultLabel.setText('Results:')
        self.resultLabel.setStyleSheet('color: black; font-weight: bold;')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    dnstester = DNSTester()
    sys.exit(app.exec_())
