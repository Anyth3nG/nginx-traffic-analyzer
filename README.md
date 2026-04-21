# Nginx Traffic Analyzer

A Python-based security tool that parses Nginx access logs, classifies HTTP traffic, detects suspicious activity, and cross-references the server version against the NVD (National Vulnerability Database) to identify known CVEs.

## What it does

- Parses all Nginx access log files including rotated logs
- Extracts IP address, requested path, status code, and user agent from each request
- Classifies each IP as PUBLIC or PRIVATE
- Flags suspicious user agents (zgrab, Go-http-client, nikto, sqlmap, etc.)
- Counts requests and errors per IP
- Flags IPs with high request counts or suspicious behavior
- Automatically detects the Nginx version from response headers
- Queries the NVD API for CVEs affecting that specific version
- Generates a report saved to report.txt

## Infrastructure

- AWS EC2 instance (Ubuntu) hosted in a custom VPC
- Nginx web server with server_tokens enabled to expose version in headers
- Log rotation configured via logrotate

## Usage

```bash
python3 parse.py IP_OF_THE_NGINX
```

## Example Output

=== NGINX TRAFFIC REPORT ===

--- IP SUMMARY ---
101.47.8.187 - 46 requests - 46 errors - SUSPICIOUS
81.5.53.52 - 4 requests - 2 errors - clean

--- CVEs found for nginx/1.24.0 ---

CVE-2023-44487
The HTTP/2 protocol allows a denial of service...

## Requirements
requests

Install with:

```bash
pip install requests
```
