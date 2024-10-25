Subdomain Enumeration Tool Documentation
# Overview
The Subdomain Enumeration Tool automates the discovery of subdomains for a specified domain by leveraging various public APIs. It integrates with services like CRT.sh, URLScan.io, VirusTotal, and SecurityTrails to collect subdomain data. Built using the Go programming language, this tool is the first component of a broader project aimed at simplifying reconnaissance tasks in cybersecurity.

# Features
   
-API Integrations: Fetches subdomains 
-Duplicate Removal: Ensures that the subdomains collected from different
services are unique and sorted.
-Output File: Saves the enumerated subdomains into a specified output file
( recon_enum.txt by default).
-Dependency Check: Verifies the availability of required external tools (e.g.,
curl, jq, httpx)

#Setup Instructions
   
  Install Go if not already installed:
sudo apt install golang-go # For Ubuntu
brew install go # For macOS

 Obtain API Keys:
Update the following variables in the code with your API keys:
CERTSPOTTER_API_KEY = "YOUR_CERTSPOTTER_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_API_KEY"
URLSCAN_API_KEY = "YOUR_URLSCAN_API_KEY"


 Usage
The tool can be run in two modes:

1. Single Domain Mode: Specify a domain using the d flag.
go run gohack.go -d example.com

2. File Input Mode: Use the f flag to specify a file containing multiple
domains.
go run gohack.go -f domains.txt

Output File: The default output file is recon_enum.txt . You can specify a
custom file using the o flag.
go run gohack.go -d example.com -o output.txt
