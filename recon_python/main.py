import sys
import socket
import whois
import requests
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton,
    QTextEdit, QVBoxLayout, QMessageBox, QTabWidget
)

class MiniReconGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MiniRecon PyQt5 툴")
        self.setGeometry(300, 300, 700, 550)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.init_info_tab(), "WHOIS & 서버정보")
        self.tabs.addTab(self.init_subdomain_tab(), "서브도메인 스캐너")

        layout = QVBoxLayout()
        layout.addWidget(self.tabs)
        self.setLayout(layout)

    # ------------------ Tab 1 ------------------
    def init_info_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.domain_input = QLineEdit()
        info_btn = QPushButton("정보 조회")
        self.info_output = QTextEdit()
        self.info_output.setReadOnly(True)

        info_btn.clicked.connect(self.lookup_info)

        layout.addWidget(QLabel("도메인 입력:"))
        layout.addWidget(self.domain_input)
        layout.addWidget(info_btn)
        layout.addWidget(self.info_output)
        tab.setLayout(layout)

        return tab

    def lookup_info(self):
        domain = self.domain_input.text()
        self.info_output.clear()

        if not domain:
            QMessageBox.warning(self, "입력 오류", "도메인을 입력해주세요!")
            return

        try:
            w = whois.whois(domain)
            self.info_output.append("[WHOIS 정보]")
            self.info_output.append(f"등록자: {w.name}")
            self.info_output.append(f"이메일: {w.emails}")
            self.info_output.append(f"네임서버: {w.name_servers}")
            self.info_output.append(f"등록일: {w.creation_date}")
            self.info_output.append(f"만료일: {w.expiration_date}\n")
        except Exception as e:
            self.info_output.append(f"[!] WHOIS 오류: {e}\n")

        try:
            ip = socket.gethostbyname(domain)
            self.info_output.append("[서버 정보]")
            self.info_output.append(f"IP 주소: {ip}")
            response = requests.get(f"http://{domain}", timeout=5)
            for k, v in response.headers.items():
                self.info_output.append(f"{k}: {v}")
        except Exception as e:
            self.info_output.append(f"[!] 서버 정보 오류: {e}\n")

    # ------------------ Tab 2 ------------------
    def init_subdomain_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.sub_input = QLineEdit()
        sub_btn = QPushButton("서브도메인 스캔")
        self.sub_output = QTextEdit()
        self.sub_output.setReadOnly(True)

        sub_btn.clicked.connect(self.scan_subdomains)

        layout.addWidget(QLabel("도메인 입력:"))
        layout.addWidget(self.sub_input)
        layout.addWidget(sub_btn)
        layout.addWidget(self.sub_output)
        tab.setLayout(layout)

        return tab

    def scan_subdomains(self):
        domain = self.sub_input.text()
        self.sub_output.clear()

        if not domain:
            QMessageBox.warning(self, "입력 오류", "도메인을 입력해주세요!")
            return

        wordlist = ["www", "mail", "ftp", "dev", "test", "api", "blog", "m", "shop"]
        found = []

        for sub in wordlist:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                self.sub_output.append(f"[✔] 발견됨: {subdomain} → {ip}")
                found.append(subdomain)
            except:
                pass

        if not found:
            self.sub_output.append("[!] 서브도메인을 찾지 못했어요.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MiniReconGUI()
    window.show()
    sys.exit(app.exec_())
