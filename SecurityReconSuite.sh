#!/bin/bash

# Function to clear the screen
clear_screen() {
    clear
}

# Function to display the menu banner
banner() {
    clear_screen
    echo -e "\e[32m**************\e[34mCONTENTS\e[32m***************\e[0m"
    menu_items=(
        "Domain Ownership Lookup"
        "Domain Name Resolver"
        "Web Technology Analyzer"
        "GeoIP finder"
        "Network Mapper"
        "Cloudflare CDN Security Checker"
        "Robots.txt Analyzer"
        "Security Barrier Detector"
        "URL Extractor"
        "HTTP Header Inspector"
        "Route Tracker"
        "Refresh Tool"
        "Close Application"
    )
    for i in "${!menu_items[@]}"; do
        echo -e "\e[32m*\e[35m $((i + 1)). ${menu_items[$i]} \e[32m*\e[0m"
    done
    echo -e "\e[32m****************************************\e[0m"
    read -p "Please choose an option: " choice
    handle_choice "$choice"
}

# Function for WHOIS lookup
whois_lookup() {
    read -p $'\e[36mEnter the website or IP address: \e[0m' site
    whois "$site"
    read -p $'\e[31mPress any key to continue\e[0m'
    banner
}

# Function for DNS lookup
dns_lookup() {
    read -p $'\e[35mEnter the IP address: \e[32m' site
    echo -e "\e[0m"
    nslookup -type=any "$site"
    read -p $'\e[31mPress any key
     to continue\e[0m'
    banner
}

# Function for Web Technology Analyzer
web_technology_detection() {
    read -p $'\e[36mEnter 1 to enter the website or 2 to enter the IP address: \e[0m' user_input
    if [[ "$user_input" == "1" ]]; then
        read -p $'\e[35mEnter the website: \e[32m' site
    elif [[ "$user_input" == "2" ]]; then
        read -p $'\e[35mEnter the IP address: \e[32m' site
    else
        echo -e "\e[31mInvalid choice\e[0m"
        read -p $'\e[31mPress any key to continue\e[0m'
        banner
        return
    fi
    echo -e "\e[0m"
    whatweb -a 3 -v "$site"
    read -p $'\e[31mPress any key to continue\e[0m'
    banner
}

# Function for GeoIP lookup
ip_locator() {
    read -p $'\e[36mEnter the IP address: \e[0m' ip_address
    # Validate the IP address
    if [[ ! "$ip_address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "\e[31mInvalid IP address.\e[0m"
        read -p $'\e[31mPress any key to continue\e[0m'
        banner
        return
    fi
    url="https://ipinfo.io/$ip_address/json"
    echo -e "\e[37mFetching location data for IP: $ip_address...\e[0m"
    response=$(curl -s "$url")
    if [[ $? -eq 0 ]]; then
        echo "$response" | jq -r 'del(.readme) | to_entries[] | "\(.key): \(.value)"' | while IFS= read -r line; do
            echo -e "\e[33m$line\e[0m"
        done
    else
        echo -e "\e[31mError fetching data\e[0m"
    fi
    read -p $'\e[31mPress any key to continue\e[0m'
    banner
}

# Function for Nmap scan
nmap_scan() {
    read -p $'\e[33mPress 1 for basic scan and 2 for extensive scan: \e[0m' scan_type
    if [[ "$scan_type" == "1" ]]; then
        read -p $'\e[36mEnter the website or the IP address: \e[0m' ip_or_site
        echo -e "\e[37mRunning a basic Nmap scan...\e[0m"
        nmap "$ip_or_site"
        echo -e "\e[31mIf the Host is down or blocking the ping probes, try the extensive scan (option 2). Press any key to continue\e[0m"
    elif [[ "$scan_type" == "2" ]]; then
        read -p $'\e[36mEnter the website or the IP address: \e[0m' ip_or_site
        echo -e "\e[33mTHIS SCAN WILL TAKE SOME TIME, SIT BACK AND RELAX!\e[0m"
        sudo nmap -sS -sV -vv --top-ports 1000 -T4 -O "$ip_or_site"
        read -p $'\e[31mPress any key to continue\e[0m'
    else
        echo -e "\e[31mPlease choose a valid option! Press Enter to continue\e[0m"
    fi
    read -p ""
    banner
}

# Function for Cloudflare CDN Security Checker
cloudflare_detect() {
    cloudflare_ips_url="https://www.cloudflare.com/ips-v4/"
    cloudflare_ips=$(curl -s "$cloudflare_ips_url")
    if [[ -n "$cloudflare_ips" ]]; then
        while true; do
            read -p $'\e[33mEnter the IP address to check: \e[0m' user_ip
            if [[ "$user_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                if echo "$cloudflare_ips" | grep -q "$user_ip"; then
                    echo -e "\e[32mThe IP $user_ip is a Cloudflare IP.\e[0m"
                else
                    echo -e "\e[31mThe IP $user_ip is not a Cloudflare IP.\e[0m"
                fi
                break
            else
                echo -e "\e[31mInvalid IP address. Please try again.\e[0m"
            fi
        done
    else
        echo -e "\e[31mCould not retrieve Cloudflare IP ranges to check.\e[0m"
    fi
    read -p $'\e[31mPress any key to continue\e[0m'
    banner
}

# Function for Robots.txt Analyzer
fetch_robots_txt() {
    read -p $'\e[32mEnter the website address (DNS only): \e[0m' website
    [[ ! "$website" =~ ^http[s]?:// ]] && website="http://$website"
    url="$website/robots.txt"
    headers="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    response=$(curl -s -A "$headers" "$url")
    if [[ $? -eq 0 ]]; then
        echo -e "\e[33mContents of robots.txt:\n$response\e[0m"
    else
        echo -e "\e[31mFailed to fetch robots.txt or it does not exist.\e[0m"
    fi
    read -p $'\e[31mPress any key to continue\e[0m'
    banner
}

# Function for Security Barrier Detector (WAF Check)
waf_check() {
    read -p $'\e[33mEnter the website or the IP address: \e[0m' target
    echo -e "Checking for WAF on $target"
    wafw00f "$target"
    read -p $'\e[31mPress any key to continue\e[0m'
    banner
}

# Function for URL Extractor
extract_urls() {
    read -p $'\e[33mEnter the website or IP address: \e[0m' site
    headers="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    response=$(curl -s -A "$headers" "$site")
    if [[ $? -eq 0 ]]; then
        urls=$(echo "$response" | grep -oP 'href="\K[^"]+' | sort -u)
        echo -e "\e[32mFollowing URLs were found embedded in the web page:\n$urls\e[0m"
    else
        echo -e "\e[31mFailed to fetch the webpage.\e[0m"
    fi
    read -p $'\e[31mPress any key to continue\e[0m'
    banner
}

# Function for HTTP Header Inspector
get_http_headers() {
    read -p $'\e[32mEnter the website address (without http://): \e[0m' site
    [[ ! "$site" =~ ^http[s]?:// ]] && site="http://$site"
    response=$(curl -I -s "$site")
    if [[ $? -eq 0 ]]; then
        echo -e "\e[33mHTTP Headers for $site:\n$response\e[0m"
    else
        echo -e "\e[31mFailed to retrieve headers.\e[0m"
    fi
    read -p $'\e[31mPress any key to continue\e[0m'
    banner
}

# Function for Route Tracker (Traceroute)
get_hostname() {
    read -p $'\e[33mEnter the website address (with or without https://): \e[0m' website
    website=${website#https://}
    website=${website#http://}
    website=${website%/}
    if [[ "$website" =~ www\. ]] || [[ "$website" =~ \. ]]; then
        mtr --report --report-wide --json -c 5 -s 120 "$website"
    else
        echo -e "\e[32mPlease enter a valid website address.\e[0m"
    fi
    read -p $'\e[31mPress any key to continue\e[0m'
    banner
}

# Function to refresh the tool
reloaded() {
    read -p $'\e[31mPress any key to continue...\e[0m'
    echo -e "\e[31mReloading...\e[0m"
    banner
}

# Function to exit the tool
exit_tool() {
    echo -e "\e[31mExiting...\e[0m"
    exit 0
}

# Function to handle menu choices
handle_choice() {
    case "$1" in
        1) whois_lookup ;;
        2) dns_lookup ;;
        3) web_technology_detection ;;
        4) ip_locator ;;
        5) nmap_scan ;;
        6) cloudflare_detect ;;
        7) fetch_robots_txt ;;
        8) waf_check ;;
        9) extract_urls ;;
        10) get_http_headers ;;
        11) get_hostname ;;
        12) reloaded ;;
        13) exit_tool ;;
        *) echo -e "\e[31mInvalid choice, please try again.\e[0m"
           banner ;;
    esac
}

# Main function to start the script
banner
