package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
)

var (
	CERTSPOTTER_API_KEY    = "YOUR_CERTSPOTTER_API_KEY"
	VIRUSTOTAL_API_KEY     = "YOUR_VIRUSTOTAL_API_KEY"
	SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_API_KEY"
	NETLAS_API_KEY         = "YOUR_NETLAS_API_KEY"
	CENUYS_API_KEY         = "YOUR_CENUYS_API_KEY"
	URLSCAN_API_KEY        = "YOUR_URLSCAN_API_KEY"
	SHODAN_API_KEY         = "YOUR_SHODAN_API_KEY"

	inputType  string
	inputFile  string
	outputFile string = "recon_enum.txt"
	domain     string
)

// Utility functions for printing
func printGreen(msg string) {
	fmt.Printf("\033[32m%s\033[0m\n", msg)
}

func printRed(msg string) {
	fmt.Printf("\033[31m%s\033[0m\n", msg)
}

func printYellow(msg string) {
	fmt.Printf("\033[33m%s\033[0m\n", msg)
}

// CRT.sh Enumeration
func enumerateCRTSh(domain string) []string {
	resp, err := http.Get(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
	if err != nil {
		log.Fatalf("Error fetching from crt.sh: %v", err)
	}
	defer resp.Body.Close()

	var crtshResp []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&crtshResp); err != nil {
		log.Fatalf("Error decoding JSON from crt.sh: %v", err)
	}

	var results []string
	for _, entry := range crtshResp {
		nameValue, ok := entry["name_value"].(string)
		if ok {
			results = append(results, strings.Replace(nameValue, "*.", "", -1))
		}
	}
	return uniqueSorted(results)
}

// URLScan.io Enumeration
type SearchResult struct {
	Results []struct {
		Page struct {
			Domain string `json:"domain"`
		} `json:"page"`
	} `json:"results"`
}

func enumerateUrlscan(domain string) ([]string, error) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set the API key in the header
	req.Header.Set("API-Key", URLSCAN_API_KEY)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result SearchResult
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, err
	}

	domainSet := make(map[string]bool)
	for _, res := range result.Results {
		domainSet[res.Page.Domain] = true
	}

	var domains []string
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains, nil
}

// VirusTotal Enumeration
func enumerateVirusTotal(domain string) []string {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains", domain)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("x-apikey", VIRUSTOTAL_API_KEY)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error fetching from VirusTotal: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalf("Error response from VirusTotal: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("Error decoding JSON from VirusTotal: %v", err)
	}

	var subdomains []string
	if data, ok := result["data"].([]interface{}); ok {
		for _, item := range data {
			if subdomain, ok := item.(map[string]interface{})["id"].(string); ok {
				subdomains = append(subdomains, subdomain)
			}
		}
	}
	return uniqueSorted(subdomains)
}

// SecurityTrails Enumeration
func enumerateSecurityTrails(domain string) []string {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("APIKEY", SECURITYTRAILS_API_KEY)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error fetching from SecurityTrails: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalf("Error response from SecurityTrails: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("Error decoding JSON from SecurityTrails: %v", err)
	}

	var subdomains []string
	if data, ok := result["subdomains"].([]interface{}); ok {
		for _, item := range data {
			if subdomain, ok := item.(string); ok {
				subdomains = append(subdomains, subdomain)
			}
		}
	}
	return uniqueSorted(subdomains)
}

// Certspotter Enumeration
func enumerateCertspotter(domain string) []string {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true", domain)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+CERTSPOTTER_API_KEY)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error fetching from Certspotter: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalf("Error response from Certspotter: %s", resp.Status)
	}

	var result []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("Error decoding JSON from Certspotter: %v", err)
	}

	var subdomains []string
	for _, item := range result {
		if names, ok := item["dns_names"].([]interface{}); ok {
			for _, name := range names {
				if subdomain, ok := name.(string); ok {
					subdomains = append(subdomains, subdomain)
				}
			}
		}
	}
	return uniqueSorted(subdomains)
}

// Unique and sort subdomains
func uniqueSorted(subdomains []string) []string {
	subdomainMap := make(map[string]bool)
	for _, subdomain := range subdomains {
		subdomainMap[subdomain] = true
	}

	var uniqueSubdomains []string
	for subdomain := range subdomainMap {
		uniqueSubdomains = append(uniqueSubdomains, subdomain)
	}

	sort.Strings(uniqueSubdomains)
	return uniqueSubdomains
}

// Checking dependencies
func checkDependencies(dependencies []string) {
	for _, dep := range dependencies {
		_, err := exec.LookPath(dep)
		if err != nil {
			log.Fatalf("Error: '%s' is not installed. Please install it and re-run the program.", dep)
		}
	}
}

// Process the domain and write results to file
func processSubdomainEnum(domain string) {
	printYellow(fmt.Sprintf("[+] Running subdomain enumeration for %s", domain))

	// Collect subdomains from different services
	subdomains := enumerateCRTSh(domain)

	urlscanSubdomains, err := enumerateUrlscan(domain)
	if err != nil {
		log.Fatalf("Error enumerating using urlscan.io: %v", err)
	}
	subdomains = append(subdomains, urlscanSubdomains...)

	virustotalSubdomains := enumerateVirusTotal(domain)
	subdomains = append(subdomains, virustotalSubdomains...)

	securitytrailsSubdomains := enumerateSecurityTrails(domain)
	subdomains = append(subdomains, securitytrailsSubdomains...)

	certspotterSubdomains := enumerateCertspotter(domain)
	subdomains = append(subdomains, certspotterSubdomains...)

	// Remove duplicates and sort
	subdomains = uniqueSorted(subdomains)

	// Save results to file
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening output file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, subdomain := range subdomains {
		_, err := writer.WriteString(subdomain + "\n")
		if err != nil {
			log.Fatalf("Error writing to file: %v", err)
		}
	}
	writer.Flush()
	printGreen(fmt.Sprintf("[+] Subdomain enumeration for %s completed.", domain))
}

// Remove duplicates and sort file content alphabetically
func removeDuplicatesAndSortFile(filename string) {
	// Open the file for reading
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	// Use a map to track unique subdomains
	subdomainSet := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		subdomainSet[line] = true
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	// Collect unique subdomains and sort them alphabetically
	var subdomains []string
	for subdomain := range subdomainSet {
		subdomains = append(subdomains, subdomain)
	}
	sort.Strings(subdomains)

	// Open the file again for writing (truncating it first)
	file, err = os.OpenFile(filename, os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening file for writing: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, subdomain := range subdomains {
		_, err := writer.WriteString(subdomain + "\n")
		if err != nil {
			log.Fatalf("Error writing to file: %v", err)
		}
	}
	writer.Flush()

	fmt.Println("[+] Duplicates removed and subdomains sorted.")
}

func main() {
	flag.StringVar(&inputFile, "f", "", "Input file with list of domains")
	flag.StringVar(&domain, "d", "", "Single domain to enumerate")
	flag.StringVar(&outputFile, "o", "recon_enum.txt", "Output file to save results")
	flag.Parse()

	if inputFile == "" && domain == "" {
		printRed("Error: You must specify either -f for file or -d for domain!")
		flag.Usage()
		os.Exit(1)
	}

	checkDependencies([]string{"curl", "jq", "httpx", "httprobe"})

	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			log.Fatalf("Error opening input file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			processSubdomainEnum(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading input file: %v", err)
		}
	} else {
		processSubdomainEnum(domain)
	}
	// Call the function to remove duplicates and sort the file content
	removeDuplicatesAndSortFile(outputFile)

	printRed(fmt.Sprintf("Saving output to file: %s", outputFile))
}
