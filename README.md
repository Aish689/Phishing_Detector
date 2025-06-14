Phishing URL Detection System with Email Alert (Python)

 Description:

This is an intelligent **Phishing URL Detection Tool** developed in Python, designed to automatically detect suspicious URLs in various input sources such as `.txt`, `.html`, and `.eml` files. Upon detecting a potentially dangerous or phishing URL, the system sends an **email alert** using Mailtrap’s SMTP service for safe testing purposes. 

The system also generates detailed CSV and TXT reports and offers real-time, color-coded console output to clearly indicate the detection status.


 Key Features:

✔️ Detects suspicious URLs based on:
- Presence of phishing keywords (e.g., `login`, `account`, `update`)
- Use of raw IP addresses
- Misleading '@' symbols in URLs
- Long or unusual subdomain/folder structures

✔️ Input Sources:
- `urls.txt` file — simple URL list
- `sample.html` — extract URLs from HTML content
- `sample.eml` — parse and check URLs in email files

✔️ Email Alert System:
- Sends instant email alerts to a configured recipient when a suspicious URL is found.
- Configured to use **Mailtrap SMTP** for safe testing.

✔️ Report Generation:
- Outputs results to both `report.csv` (for data analysis) and `report.txt` (for quick reading).

✔️ Terminal Output:
- Real-time URL check results with colored highlights using **Colorama**.



 Requirements

- Python 3.x
- Packages listed in `requirements.txt`:
  - `beautifulsoup4`
  - `colorama`

Install all dependencies with:
```bash
pip install -r requirements.txt
