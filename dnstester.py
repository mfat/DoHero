import sys
import dns.message
import dns.rdatatype
import httpx
import subprocess
from urllib.parse import urlparse
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QTextEdit, QInputDialog, QMessageBox

class DoHApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set up the window
        self.setWindowTitle('DNS-over-HTTPS Tester')
        self.setGeometry(100, 100, 500, 550)

        # Add a label for the DoH server URL
        self.doh_label = QLabel('DNS-over-HTTPS Server:', self)
        self.doh_label.move(50, 50)

        # Add a text field for the DoH server URL
        self.doh_field = QLineEdit('https://dns.google/dns-query', self)
        self.doh_field.setGeometry(200, 50, 250, 30)

        # Add a label for the domain name
        self.domain_label = QLabel('Domain Name:', self)
        self.domain_label.move(50, 100)

        # Add a text field for the domain name
        self.domain_field = QLineEdit('facebook.com', self)
        self.domain_field.setGeometry(200, 100, 250, 30)

        # Add a button to send the DoH query
        self.query_button = QPushButton('Query', self)
        self.query_button.move(200, 150)
        self.query_button.clicked.connect(self.send_query)

        # Add a text area to display the query result
        self.result_area = QTextEdit(self)
        self.result_area.setGeometry(50, 200, 400, 200)
        self.result_area.setReadOnly(True)

        # Add a button to set the DoH server as the default DNS resolver
        self.use_server_button = QPushButton('Use this server', self)
        self.use_server_button.move(100, 420)
        self.use_server_button.clicked.connect(self.set_doh_server)

        # Add a button to reset the DNS resolver to the default value
        self.reset_button = QPushButton('Reset to Default', self)
        self.reset_button.move(300, 420)
        self.reset_button.clicked.connect(self.reset_dns)

    def send_query(self):
        # Get the DoH server URL and domain name from the text fields
        doh_url = self.doh_field.text()
        domain = self.domain_field.text()

        # Create a DNS query message
        query = dns.message.make_query(domain, dns.rdatatype.A)

        # Encode the DNS query in the DoH format
        body = query.to_wire()
        headers = {'Content-Type': 'application/dns-message'}

        # Send the DNS query over DoH
        try:
            response = httpx.post(doh_url, headers=headers, content=body)
        except httpx.HTTPError as e:
            self.result_area.setText(f'Error sending DNS query: {e}')
            return

        # Parse the DNS response
        response_message = dns.message.from_wire(response.content)
        answer = response_message.answer[0]

        # Display the DNS answer section in the result area
        self.result_area.setText(str(answer))

    def set_doh_server(self):
        # Get the DoH server URL from the text field
        doh_url = self.doh_field.text()

        # Show a dialog to prompt the user for their sudo password
        password, ok = QInputDialog.getText(self, 'Enter Password', 'Enter your sudo password:', QLineEdit.Password)
        if not ok:
            return

        # Create the DoH configuration file with root privileges
        try:
            config_text = f'[Resolve]\nDNSOverHTTPS=yes\nDNSOverHTTPSURL={doh_url}\n'
            echo_process = subprocess.Popen(['echo', config_text], stdout=subprocess.PIPE)
            subprocess.check_call(['sudo', 'tee', '/etc/systemd/resolved.conf.d/doh.conf'], stdin=echo_process.stdout)
            subprocess.check_call(['sudo', 'systemctl','restart', 'systemd-resolved.service'])
            self.result_area.setText(f'DoH server {doh_url} set as default DNS resolver')
        except subprocess.CalledProcessError:
            self.result_area.setText('Error setting DoH server as default DNS resolver')
        except Exception as e:
            self.result_area.setText(f'Error: {e}')


    def reset_dns(self):
        # Show a dialog to prompt the user for their sudo password
        password, ok = QInputDialog.getText(self, 'Enter Password', 'Enter your sudo password:', QLineEdit.Password)
        if not ok:
            return

        # Reset the DNS resolver to the default value and remove the DoH configuration file
        try:
            subprocess.check_call(['echo', password, '|', 'sudo', '-S', 'systemctl', 'restart', 'systemd-resolved.service'], shell=True)
            subprocess.check_call(['sudo', 'rm', '-f', '/etc/systemd/resolved.conf.d/doh.conf'])
            self.result_area.setText('DNS resolver reset to default value and DoH configuration file removed')
        except subprocess.CalledProcessError:
            self.result_area.setText('Error resetting DNS resolver or removing DoH configuration file')
        except Exception as e:
            self.result_area.setText(f'Error: {e}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DoHApp()
    window.show()
    sys.exit(app.exec_())
