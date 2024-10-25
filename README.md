# Subdomain-Enumeration
Documentation
1. Overview
The Subdomain Enumeration Tool is designed to automate the process of
discovering subdomains for a given domain using various public APIs. The tool
integrates with services such as CRT.sh, URLScan.io, VirusTotal, and
SecurityTrails to gather subdomain data. It is built using the Go programming
language and is the first part of a larger project aimed at simplifying
reconnaissance tasks for cybersecurity purposes.
2. Features
API Integrations: Fetches subdomains from multiple services:
CRT.sh
URLScan.io
VirusTotal
SecurityTrails
Duplicate Removal: Ensures that the subdomains collected from different
services are unique and sorted.
Output File: Saves the enumerated subdomains into a specified output file
( recon_enum.txt by default).
Dependency Check: Verifies the availability of required external tools (e.g.,
curl, jq, httpx).
3. Prerequisites
Go 1.18+
External Dependencies:
curl
jq
Project Documentation 2
httpx
httprobe
Make sure these tools are installed on the system before running the program.
4. Setup Instructions
1. Install Go Dependencies:
Install Go if not already installed:
sudo apt install golang-go # For Ubuntu
brew install go # For macOS
2. Obtain API Keys:
Get API keys from the following services:
CRT.sh (no API key required)
URLScan.io
VirusTotal
SecurityTrails
Update the following variables in the code with your API keys:
CERTSPOTTER_API_KEY = "YOUR_CERTSPOTTER_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_API_KEY"
URLSCAN_API_KEY = "YOUR_URLSCAN_API_KEY"
5. Usage
The tool can be run in two modes:
1. Single Domain Mode: Specify a domain using the d flag.
go run gohack.go -d example.com
2. File Input Mode: Use the f flag to specify a file containing multiple
domains.
Project Documentation 3
go run gohack.go -f domains.txt
3. Output File: The default output file is recon_enum.txt . You can specify a
custom file using the o flag.
go run gohack.go -d example.com -o output.txt
6. Tool Components
6.1. API Enumerations
CRT.sh Enumeration:
The tool queries 
CRT.sh to retrieve a list of subdomains associated with the given domain by
looking at certificate transparency logs.
Example code:
func enumerateCRTSh(domain string) []string {
 // Code to fetch data from CRT.sh
}
URLScan.io Enumeration:
Uses the 
URLScan.io API to search for subdomains related to the domain in question.
Example code:
func enumerateUrlscan(domain string) ([]string, error) {
 // Code to fetch data from URLScan.io
}
VirusTotal Enumeration:
Retrieves subdomains by querying VirusTotal’s database of domains and IP
addresses.
Example code:
Project Documentation 4
func enumerateVirusTotal(domain string) []string {
 // Code to fetch data from VirusTotal
}
SecurityTrails Enumeration:
Fetches subdomain data from SecurityTrails’ extensive domain information
database.
Example code:
func enumerateSecurityTrails(domain string) []string {
 // Code to fetch data from SecurityTrails
}
6.2. Unique Subdomain Sorting
Ensures that subdomains collected from different sources are unique and
sorted alphabetically before being saved to the output file.
func uniqueSorted(subdomains []string) []string {
 // Code to remove duplicates and sort
}
7. Error Handling
The tool includes error handling for various scenarios, such as:
Failure to connect to the API.
Invalid JSON responses.
File I/O errors when reading or writing the output.
Example:
if err != nil {
 log.Fatalf("Error: %v", err)
}
8. Example Output
Project Documentation 5
When the tool completes the enumeration, the output file contains a sorted list
of unique subdomains:
blog.example.com
mail.example.com
shop.example.com
The output will vary depending on the APIs used and the data they provide.
9. Future Improvements
Add more subdomain enumeration APIs (e.g., Shodan, Censys).
Implement concurrency to improve performance.
Add more flexible output formats (e.g., JSON, CSV).
