import re
import os
import csv
import smtplib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from email import message_from_file
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from colorama import init, Fore, Style

init(autoreset=True)

# Email Alert Configuration
EMAIL_ALERTS = True  # Set to False to disable email alerts
SMTP_SERVER = 'sandbox.smtp.mailtrap.io'
SMTP_PORT = 2525
SENDER_EMAIL = '7b8c130e89eff4'  # Your Mailtrap username
#SENDER_PASSWORD = 'e7bf40bfa6f822'  # Your Mailtrap password'     # Change this to your email
SENDER_PASSWORD = 'e7bf40bfa6f822'         # Change this to your app password or email password
RECEIVER_EMAIL = 'receiveremail@gmail.com'  # Change this to the destination email

def send_email_alert(suspicious_url, reasons):
    if not EMAIL_ALERTS:
        return
    try:
        subject = f"[ALERT] Suspicious URL Detected!"
        body = f"The following URL was flagged as suspicious:\n\n{suspicious_url}\n\nReasons:\n" + "\n".join(reasons)

        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(Fore.RED + "[+] Email alert sent!")
    except Exception as e:
        print(Fore.RED + f"[!] Failed to send email alert: {e}")

def is_suspicious(url):
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'banking']
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    
    report = []

    # Check 1: Suspicious keywords
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            msg = f"Suspicious: URL contains keyword '{keyword}'"
            print(Fore.YELLOW + "[!] " + msg)
            report.append(msg)
            return True, report

    # Check 2: IP address in URL
    if re.search(ip_pattern, url):
        msg = "Suspicious: URL contains IP address"
        print(Fore.YELLOW + "[!] " + msg)
        report.append(msg)
        return True, report

    # Check 3: '@' in URL
    if '@' in url:
        msg = "Suspicious: URL contains '@' symbol"
        print(Fore.YELLOW + "[!] " + msg)
        report.append(msg)
        return True, report

    # Check 4: Too many subdomains/folders
    parts = url.split('/')
    if len(parts) > 4:
        msg = "Suspicious: URL has too many subdomains or folders"
        print(Fore.YELLOW + "[!] " + msg)
        report.append(msg)
        return True, report

    msg = "URL seems safe."
    print(Fore.GREEN + "[+] " + msg)
    report.append(msg)
    return False, report

def extract_urls_from_html(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f, 'lxml')
        return [a['href'] for a in soup.find_all('a', href=True)]

def extract_urls_from_eml(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        msg = message_from_file(f)
        urls = []
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                soup = BeautifulSoup(part.get_payload(decode=True), 'lxml')
                urls += [a['href'] for a in soup.find_all('a', href=True)]
        return urls

def process_url_list(url_list, report_lines, csv_data):
    for url in url_list:
        print(Fore.CYAN + f"\nChecking URL: {url}")
        report_lines.append(f"\nChecking URL: {url}")
        suspicious, report = is_suspicious(url)
        report_lines.extend(report)

        # For CSV report
        status = "Suspicious" if suspicious else "Safe"
        reasons = " | ".join(report)
        csv_data.append([url, status, reasons])

        # Email alert if suspicious
        if suspicious:
            send_email_alert(url, report)

def main():
    report_lines = ["Phishing Detection Report\n"]
    csv_data = [["URL", "Status", "Details"]]

    # 1. Check URLs from urls.txt
    if os.path.exists("urls.txt"):
        with open("urls.txt", "r") as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
        print(Fore.MAGENTA + "\n[***] Scanning URLs from urls.txt...")
        report_lines.append("\n[***] Scanning URLs from urls.txt...")
        process_url_list(urls, report_lines, csv_data)

    # 2. Check URLs from HTML file (webpage)
    html_file = "sample.html"  
    if os.path.exists(html_file):
        print(Fore.MAGENTA + "\n[***] Scanning URLs from HTML file...")
        report_lines.append("\n[***] Scanning URLs from HTML file...")
        html_urls = extract_urls_from_html(html_file)
        process_url_list(html_urls, report_lines, csv_data)

    # 3. Check URLs from EML (email file)
    eml_file = "sample.eml"  
    if os.path.exists(eml_file):
        print(Fore.MAGENTA + "\n[***] Scanning URLs from EML file...")
        report_lines.append("\n[***] Scanning URLs from EML file...")
        eml_urls = extract_urls_from_eml(eml_file)
        process_url_list(eml_urls, report_lines, csv_data)

    # Write TXT Report
    with open("report.txt", "w") as report_file:
        report_file.write('\n'.join(report_lines))
    print(Fore.GREEN + "\n[+] Report generated: report.txt")

    # Write CSV Report
    with open("report.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(csv_data)
    print(Fore.GREEN + "[+] Report generated: report.csv")

if __name__ == "__main__":
    main()

