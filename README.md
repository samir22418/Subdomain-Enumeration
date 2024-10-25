Subdomain Enumeration Tool Documentation
1. Overview
The Subdomain Enumeration Tool automates the discovery of subdomains for a specified domain by leveraging various public APIs. It integrates with services like CRT.sh, URLScan.io, VirusTotal, and SecurityTrails to collect subdomain data. Built using the Go programming language, this tool is the first component of a broader project aimed at simplifying reconnaissance tasks in cybersecurity.

2. Features
API Integrations: Collects subdomains from multiple services, including:

CRT.sh
URLScan.io
VirusTotal
SecurityTrails
Duplicate Removal: Ensures that the collected subdomains are unique and sorted.

Output File: Saves the discovered subdomains to a specified output file (default: recon_enum.txt).

Dependency Check: Verifies the availability of necessary external tools such as curl, jq, and httpx.

3. Prerequisites
Go Version: 1.18 or later
External Dependencies:
curl
jq
Ensure these tools are installed on your system before running the program.

4. Setup Instructions
Install Go:

For Ubuntu:
bash
Copy code
sudo apt install golang-go
For macOS:
bash
Copy code
brew install go
Obtain API Keys: Acquire API keys from the following services:

CRT.sh (no API key required)
URLScan.io
VirusTotal
SecurityTrails
Update the following variables in the code with your API keys:

go
Copy code
CERTSPOTTER_API_KEY = "YOUR_CERTSPOTTER_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_API_KEY"
URLSCAN_API_KEY = "YOUR_URLSCAN_API_KEY"
5. Usage
The tool can be executed in two modes:

Single Domain Mode: Specify a single domain using the -d flag.

bash
Copy code
go run gohack.go -d example.com
File Input Mode: Provide a file containing multiple domains using the -f flag.

bash
Copy code
go run gohack.go -f domains.txt
Custom Output File: By default, the output is saved to recon_enum.txt. You can specify a different output file using the -o flag.

bash
Copy code
go run gohack.go -d example.com -o output.txt
6. Tool Components
6.1 API Enumerations
CRT.sh Enumeration: Queries CRT.sh for a list of subdomains associated with the given domain from certificate transparency logs.

go
Copy code
func enumerateCRTSh(domain string) []string {
    // Code to fetch data from CRT.sh
}
URLScan.io Enumeration: Utilizes the URLScan.io API to find subdomains related to the specified domain.

go
Copy code
func enumerateUrlscan(domain string) ([]string, error) {
    // Code to fetch data from URLScan.io
}
VirusTotal Enumeration: Retrieves subdomains by querying VirusTotal’s extensive database.

go
Copy code
func enumerateVirusTotal(domain string) []string {
    // Code to fetch data from VirusTotal
}
SecurityTrails Enumeration: Gathers subdomain information from SecurityTrails’ comprehensive domain data repository.

go
Copy code
func enumerateSecurityTrails(domain string) []string {
    // Code to fetch data from SecurityTrails
}
6.2 Unique Subdomain Sorting
This function ensures that subdomains collected from different sources are unique and sorted alphabetically before being saved.

go
Copy code
func uniqueSorted(subdomains []string) []string {
    // Code to remove duplicates and sort
}
7. Error Handling
The tool includes error handling for various scenarios, such as:

Connection failures to the API.
Invalid JSON responses.
File I/O errors during reading or writing the output.
Example error handling:

go
Copy code
if err != nil {
    log.Fatalf("Error: %v", err)
}
8. Example Output
Upon completion of the enumeration, the output file will contain a sorted list of unique subdomains:

Copy code
blog.example.com
mail.example.com
shop.example.com
The output may vary based on the APIs used and the data they provide.

9. Future Improvements
Add more subdomain enumeration APIs (e.g., Shodan, Censys).
Implement concurrency to enhance performance.
Introduce additional output formats (e.g., JSON, CSV).
