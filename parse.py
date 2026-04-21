#!/usr/bin/env python3
from collections import Counter
import re, ipaddress, glob, requests, argparse

parser = argparse.ArgumentParser()

parser.add_argument("ip")
args = parser.parse_args()

version = requests.get(f"http://{args.ip}").headers["Server"]
version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', version)
version = version_match.group(1)

url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*&resultsPerPage=5")
log_files = glob.glob('/var/log/nginx/access.log*')
response = requests.get(url)
python_dic = response.json()
suspicious_agents = ['zgrab', 'libredtail-http', 'Go-http-client', 'curl', 'python-requests', 'nmap', 'masscan', 'nikto', 'sqlmap']
pattern = r'(\d+\.\d+\.\d+\.\d+).*\"[^ ]* ([^ ]*) [^ ]*\" (\d{3}).*"(.*)"$'
suspicious_ips = set()
ip_counts = Counter()
error_count = Counter()
report = open("report.txt", "w")

for file in log_files:
    with open (file, "r") as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                ip = ipaddress.ip_address(match.group(1))
                if ip.is_private:
                    check_ip = "PRIVATE"
                else:
                    check_ip = "PUBLIC"
                if any(agent in match.group(4) for agent in suspicious_agents):
                    print("[SUSPICIOUS]", end=" ")
                    suspicious_ips.add(match.group(1))
                if int(match.group(3)) >= 400:
                    error_count[match.group(1)] += 1

                ip_counts[match.group(1)] += 1
                print(f"{match.group(1)} {match.group(2)} {match.group(3)} {check_ip} {match.group(4)}")

print("")
report = open("report.txt", "w")
report.write("=== NGINX TRAFFIC REPORT ===\n")
report.write("\n--- IP SUMMARY ---\n")
for ip, count in ip_counts.items():
    if count >= 10 or ip in suspicious_ips:
        status = "SUSPICIOUS"
    else:
        status = "clean"
    print(f"{ip} - {count} requests - {error_count[ip]} errors - {status}")
    report.write(f"{ip} - {count} requests - {error_count[ip]} errors - {status}\n")

print("\n --- CVEs found for nginx/1.24.0 ---")
report.write("\n--- CVEs found for nginx/1.24.0 ---\n")
for item in python_dic["vulnerabilities"]:
        print(item["cve"]["id"])
        print(item["cve"]["descriptions"][0]["value"])
        report.write(f"{item['cve']['id']}\n")
        report.write(f"{item['cve']['descriptions'][0]['value']}\n")
report.close()