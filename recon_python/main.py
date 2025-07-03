import sys
import socket
import whois
import requests
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit,
    QPushButton, QTextEdit, QVBoxLayout, QMessageBox
)

class MiniReconGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('MiniRecon')
        self.setGeometry(300, 300, 600, 500)

        self.label = QLabel('도메인을 입력하세요:')
        self.input = QLineEdit()
        self.button = QPushButton('정보 조회')
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.button.clicked.connect(self.lookup_info)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.input)
        layout.addWidget(self.button)
        layout.addWidget(self.output)

        self.setLayout(layout)

    def lookup_info(self):
        domain = self.input.text()
        self.output.clear()

        if not domain:
            QMessageBox.warning(self, "입력 오류", "도메인을 입력해주세요!")
            return

        try:
            w = whois.whois(domain)
            self.output.append("[WHOIS 정보]")
            self.output.append(f"등록자: {w.name}")
            self.output.append(f"이메일: {w.emails}")
            self.output.append(f"네임서버: {w.name_servers}")
            self.output.append(f"등록일: {w.creation_date}")
            self.output.append(f"만료일: {w.expiration_date}\n")
        except Exception as e:
            self.output.append(f"[!] WHOIS 오류: {e}\n")

        try:
            ip = socket.gethostbyname(domain)
            self.output.append("[서버 정보]")
            self.output.append(f"IP 주소: {ip}")

            response = requests.get(f"http://{domain}", timeout=5)
            for k, v in response.headers.items():
                self.output.append(f"{k}: {v}")
        except Exception as e:
            self.output.append(f"[!] 서버 정보 오류: {e}\n")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MiniReconGUI()
    window.show()
    sys.exit(app.exec_())
