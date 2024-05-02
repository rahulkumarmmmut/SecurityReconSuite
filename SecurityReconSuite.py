import os
import requests
import subprocess
import socket
import re
import time
import json
import sys
import ipaddress
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style, init
from tabulate import tabulate

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear_screen()
    print(Fore.GREEN + '**************' + Fore.BLUE + 'CONTENTS' + Fore.GREEN + '***************')
    menu_items = [
        " Domain Ownership Lookup",
        " Domain Name Resolver",
        " Web Technology Analyzer",
        " GeoIP finder",
        " Network Mapper",
        " Cloudflare CDN Security Checker",
        " Robots.txt Analyzer",
        " Security Barrier Detector",
        " URL Extractor",
        " HTTP Header Inspector",
        " Route Tracker",
        " Refresh Tool",
        " Close Application"
    ]
    for index, item in enumerate(menu_items, start=1):
        print(f"{Fore.GREEN}*{Fore.MAGENTA} {index}. {item} {Fore.GREEN}*")
    print(Fore.GREEN + '*' * 40)
    choice = input("Please choose an option: ")
    handle_choice(choice)

################################WHOIS ################################

def whois_lookup():
    site = input(Fore.CYAN + "Enter the website or IP address: ")
    result = subprocess.run(['whois', site], capture_output=True, text=True)
    print(Fore.RED + result.stdout)
    input(Fore.RED + Style.BRIGHT + "Press any key to continue")
    banner()

################################DNS-LOOKUP ################################

def dns_lookup():
    print(Fore.MAGENTA + "Enter the IP address: ", end="")
    site = input(Fore.GREEN)
    print(Style.RESET_ALL, end="")
    command = ['nslookup','-type=any',site]
    result = subprocess.run(command, capture_output=True, text=True)
    print(result.stdout)
    input(Fore.RED + Style.BRIGHT + "Press any key to continue")
    banner()


################################ WEB-TECH-DETECT3 ################################
def web_technology_detection():
    print(Fore.CYAN + "Enter 1 to enter the website or 2 to enter the IP address: ", end="")
    user_input = input()
    if user_input == "1":
        print(Fore.MAGENTA + "Enter the website: ", end="")
    elif user_input == "2":
        print(Fore.MAGENTA + "Enter the IP address: ", end="")
    else:
        print(Fore.RED + "Invalid choice")
        input(Fore.RED + Style.BRIGHT + "Press any key to continue")
        banner()
        return

    site = input(Fore.GREEN)
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if re.match(regex, site) or user_input == "2":
        print(Style.RESET_ALL, end="")
        command = ['whatweb', '-a', '3', '-v', site]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)
    else:
        print(Fore.RED + "Invalid URL/IP address")

    input(Fore.RED + Style.BRIGHT + "Press any key to continue")
    banner()


    
################################IP-INFORMATION ################################

def ip_locator():
    print(Fore.CYAN + "Enter the IP address: ", end="")
    ip_address = input()
    try:
        socket.inet_aton(ip_address)
        url = f"https://ipinfo.io/{ip_address}/json"
        print(Fore.WHITE + f"Fetching location data for IP: {ip_address}...")
        response = requests.get(url)
        response.raise_for_status()  
        data = response.json()
        data.pop('readme', None)  
        for key, value in data.items():
            print(Fore.YELLOW + f"{key.capitalize()}: {value}")

    except requests.RequestException as e:
        print(Fore.RED + "Error fetching data:", e)

    except socket.error:
        print(Fore.RED + f"{ip_address} is not a valid IP address.")

    input(Fore.RED + Style.BRIGHT + "Press any key to continue")
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()




################################ NMAP################################

def nmap_scan():
    print(Fore.YELLOW + "Press 1 for basic scan and 2 for extensive scan: ", end="")
    scan_type = input()
    
    if scan_type == "1":
        ip_or_site = input(Fore.CYAN + "Enter the website or the IP address: ")
        print(Fore.WHITE + "Running a basic Nmap scan...")
        result = subprocess.run(['nmap', ip_or_site], capture_output=True, text=True)
        print(Fore.GREEN + result.stdout)
        print(Fore.RED + Style.BRIGHT + "If the Host is down or blocking the ping probes, try the extensive scan (option 2). Press any key to continue")

    elif scan_type == "2":
        ip_or_site = input(Fore.CYAN + "Enter the website or the IP address: ")
        print(Fore.YELLOW + "THIS SCAN WILL TAKE SOME TIME, SIT BACK AND RELAX!")
        result = subprocess.run(['sudo', 'nmap', '-sS', '-sV', '-vv', '--top-ports', '1000', '-T4', '-O',  ip_or_site], capture_output=True, text=True)
        print(Fore.GREEN + result.stdout)
        print(Fore.RED + Style.BRIGHT + "Press any key to continue")

    else:
        print(Fore.RED + Style.BRIGHT + "Please choose a valid option! Press Enter to continue")

    input()  # Wait for user to press any key
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()  # Call main to return to the main menu or restart the script
  
################################ CLOUDFLARE ################################



def fetch_cloudflare_ips(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  
        return response.text.strip().split('\n')
    except requests.RequestException as e:
        print(Fore.RED + "Failed to fetch Cloudflare IP ranges:", str(e))
        return []

def is_ip_in_ranges(ip, ranges):
    ip_obj = ipaddress.ip_address(ip)
    for cidr in ranges:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    return False

def validate_ip(ip):
    ip_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    if re.match(ip_pattern, ip):
        # Further check if each octet is within the valid range (0-255)
        octets = ip.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    return False

def cloudflare_detect():
    cloudflare_ips_url = "https://www.cloudflare.com/ips-v4/"
    cloudflare_ips = fetch_cloudflare_ips(cloudflare_ips_url)
    if cloudflare_ips:
        while True:
            user_ip = input(Fore.YELLOW + "Enter the IP address to check: ")
            if validate_ip(user_ip):
                if is_ip_in_ranges(user_ip, cloudflare_ips):
                    print(Fore.GREEN + f"The IP {user_ip} is a Cloudflare IP.")
                    break
                else:
                    print(Fore.RED + f"The IP {user_ip} is not a Cloudflare IP.")
                    break
            else:
                print(Fore.RED + "Invalid IP address. Please try again.")
                
    else:
        print(Fore.RED + "Could not retrieve Cloudflare IP ranges to check.")
    input(Fore.RED + Style.BRIGHT + "Press any key to continue")    
    banner()



  
################################ROBOTS_TXT ################################

def fetch_robots_txt():
    website = input(Fore.GREEN + "Enter the website address (DNS only): ")
    if not website.startswith("http://") and not website.startswith("https://"):
        website = "http://" + website 
    try:
        url = f"{website}/robots.txt"
        headers = {'User-Agent': "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(Fore.YELLOW + "Contents of robots.txt:\n" + response.text)
        else:
            print(Fore.RED + "Failed to fetch robots.txt or it does not exist.")
    except requests.RequestException as e:
        print(Fore.RED + f"An error occurred: {str(e)}")    
    input(Fore.RED + Style.BRIGHT + "Press any key to continue")
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()    
    
################################ WAF ################################

def install_wafw00f():
    result = subprocess.run(['wafw00f', '--version'], capture_output=True, text=True)
    if result.returncode != 0:
        print('wafw00f not found, installing now...')
        if sys.platform == "darwin":  # macOS
            subprocess.run(["git", "clone", "https://github.com/EnableSecurity/wafw00f.git"], check=True)
            os.chdir("wafw00f")
            subprocess.run(["python3", "setup.py", "build"], check=True)
            subprocess.run(["python3", "setup.py", "install"], check=True)
            os.chdir("..")
            subprocess.run(["rm", "-rf", "wafw00f"])
        else:  # Assumes Linux
            subprocess.run(["sudo", "apt-get", "install", "wafw00f"], check=True)
def run_wafw00f(target):
    install_wafw00f()
    print(f"Running wafw00f on {target}")
    result = subprocess.run(['wafw00f', target], capture_output=True, text=True)
    if result.stdout:
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if '[+] The site' in line and 'WAF.' in line:
                # WAF detected
                print(Fore.GREEN + line.strip())
                break
            elif '[-]' in line and 'No WAF' in line:
                print(Fore.RED + "WAF not present")
                break

                 
def waf_check():
    target = input(Fore.YELLOW + "Enter the webiste or the IP address: ")
    run_wafw00f(target)
    input(Fore.RED + Style.BRIGHT + "Press any key to continue") 
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()

############################### HTTP LINKS ################################

def extract_urls():
    site = input(Fore.YELLOW + "Enter the website or IP address: ")
    headers = {'User-Agent': "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"}
    response = requests.get(site, headers=headers)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        anchor_tags = soup.find_all('a', href=True)
        print(Fore.GREEN + 'Following URLs were found embedded in the web page: \n')
        urls = set() 
        for tag in anchor_tags:
            href = tag['href']
            href = urljoin(site, href)
            if not href.startswith('#') and re.match(r'^https?:\/\/', href, re.I):
                urls.add(href)
        for url in urls:
            print(url)
        input(Fore.YELLOW + '\nPress any key to continue')
        os.system('cls' if os.name == 'nt' else 'clear')
        banner()  
    else:
        print(Fore.GREEN + "Failed to fetch the webpage.")
        input(Fore.YELLOW + '\nPress any key to continue')
        os.system('cls' if os.name == 'nt' else 'clear')
        banner()

################################HEADERS ################################

def get_http_headers():
    print(Fore.GREEN + "Enter the website address (without http://): ", end="")
    site = input().strip()
    regex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if re.match(regex, site):
    	if not site.startswith('http://') and not site.startswith('https://'):
        	site = 'http://' + site 
    	try:
            response = requests.head(site)
            print(Fore.YELLOW + f"HTTP Headers for {site}:")
            for key, value in response.headers.items():
                print(Fore.CYAN + f"{key}: {value}")
    	except requests.exceptions.RequestException as e:
            print(Fore.RED + "Failed to retrieve headers:")
            print(Fore.RED + str(e))
    else:
        print(Fore.RED + "Invalid URL!!")
    	
    input(Fore.RED + Style.BRIGHT + "Press any key to continue")
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()


################################ TRACEROUTE ################################

def get_hostname_from_user():
    while True:
        website = input(Fore.YELLOW + "Enter the website address (with or without https://): ")
        if website.startswith("https://"):
            website = website.replace("https://", '')  
        elif website.startswith("http://"):
            website = website.replace("http://", '')  
        website = website.rstrip('/')
        
        if website.startswith("www.") or "." in website:
            return website
        else:
            print(Fore.GREEN + "Please enter a valid website address.")


def run_mtr(hostname, use_ipv6=False, report_cycles=10, packet_size=60):
    ip_version = '-6' if use_ipv6 else '-4'
    mtr_cmd = [
        'mtr', ip_version, '--report', '--report-wide', '--json',
        '-c', str(report_cycles),
        '-s', str(packet_size),
        hostname
    ]

    try:
        print(Fore.YELLOW + f"Running MTR diagnostic on {hostname}...")
        result = subprocess.Popen(mtr_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while True:
            if result.poll() is not None:
                break
            time.sleep(1) 

        output, error = result.communicate()
        if output:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                print(Fore.RED + "Failed to parse JSON. Output was:")
                print(output)
        if error:
            print(Fore.RED + "MTR produced an error. Error was:")
            print(error)
    except Exception as e:
        print(Fore.RED + "An error occurred while running MTR:", str(e))

def print_mtr_report(mtr_data):
    if mtr_data and 'report' in mtr_data:
        headers = ['Hostname', 'IP', 'Loss%', 'Snt', 'Last', 'Avg', 'Best', 'Wrst', 'StDev']
        rows = []
        for hop in mtr_data['report']['hubs']:
            rows.append([
                hop.get('host', ''),
                hop.get('ip', ''),
                hop.get('Loss%', ''),
                hop.get('Snt', ''),
                hop.get('Last', ''),
                hop.get('Avg', ''),
                hop.get('Best', ''),
                hop.get('Wrst', ''),
                hop.get('StDev', '')
            ])
        print(tabulate(rows, headers=headers, tablefmt='grid'))
    else:
        print(Fore.RED + "No MTR data to display.")

def get_hostname():
    hostname = get_hostname_from_user()
    mtr_report = run_mtr(hostname, use_ipv6=False, report_cycles=5, packet_size=120)
    if mtr_report:
        print_mtr_report(mtr_report)
        input(Fore.RED + Style.BRIGHT + "Press any key to continue...")  
    else:
        print(Fore.RED + "Failed to obtain MTR data. Please try again.")
        input(Fore.RED + Style.BRIGHT + "Press any key to continue...") 
    banner()  
    
def reloaded():
    input(Fore.RED + Style.BRIGHT + "Press any key to continue...") 
    print(Fore.RED + "Reloading....")
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
	    

def exit():
    print(Fore.RED + "Exiting...")
    sys.exit()
    os.system('cls' if os.name == 'nt' else 'clear')
        

##########################################################

def handle_choice(choice):
    if choice == '1':
        whois_lookup()
    elif choice == '2':
        dns_lookup()
    elif choice == '3':
    	web_technology_detection()
    elif choice == '4':
    	ip_locator()
    elif choice == '5':
        nmap_scan()
    elif choice == '6':
    	cloudflare_detect()
    elif choice == '7':
    	fetch_robots_txt()
    elif choice == '8':
    	waf_check()
    elif choice == '9':
    	extract_urls()
    elif choice == '10':
    	get_http_headers()
    elif choice == '11':
    	get_hostname()
    elif choice == '12':
    	reloaded()
    elif choice == '13':
        exit()
    else:
        print(Fore.RED + "Invalid choice, please try again.")
        banner()

if __name__ == "__main__":
    banner()
