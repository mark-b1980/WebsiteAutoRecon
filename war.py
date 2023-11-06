import whois
import requests

import dns.zone
import dns.resolver

from bs4 import BeautifulSoup
from colorama import init, Fore, Style

########################################################################################
# CLI args processing
########################################################################################

# TODO: 
# 1) Check of 2 arguments are given and print usage if not
# 2) Check for -h or --help in arguments
# 3) Set URL and WORDLIST to the according values
# 4) Check if WORDLIST is readable and display error if not

URL = "http://192.168.1.2"
URL = "http://ZoneTransfer.me"
EXTS = "zip,bz2,tar,gz,tgz,tar.bz2,tar.gz,old,bak,inc,ini,xml,txt,yaml,yml,conf,cnf,config,json".split(",")
WORDLIST = ""

########################################################################################
# Functions for output and logging
########################################################################################

def usage():
    print("\nUSAGE:\n======\n")
    print("war.py [URL] [WORDLIST]\n")
    print("e.g.: war.py https://web.site /usr/share/waordlists/dirb/common.txt")

def print_info(txt=""):
    global log_file
    global Fore
    global Style
    print(txt)
    log_file.write(txt + "\n")

def print_found(txt):
    global log_file
    global Fore
    global Style
    print(f"{Fore.GREEN}{txt}{Style.RESET_ALL}")
    log_file.write(txt + "\n")

def print_error(txt):
    global log_file
    global Fore
    global Style
    print(f"{Fore.RED}{txt}{Style.RESET_ALL}")
    log_file.write(txt + "\n")


########################################################################################
# Setup Requests session
########################################################################################
session = requests.Session()
session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'})


########################################################################################
# LOG OUTPUT
########################################################################################
domain = URL.split("/")[2].lower()
with open(f"{domain}.log", "w", encoding="UTF-8") as log_file:

    ########################################################################################
    # WHOIS
    ########################################################################################
    print_info("WHOIS:")
    print_info("="*48)

    # Prettify output
    whois_info = str(whois.whois(domain))
    whois_info = whois_info.replace("{", "").replace("}", "")
    whois_info = whois_info.replace("[", "").replace("]", "")
    whois_info = whois_info.replace("\"", "").replace(",\n", "\n")
    whois_info = whois_info.lstrip()

    out = ""
    for line in whois_info.split("\n"):
        line = line.lstrip()

        # Format key
        if ": " in line:
            tmp = line.split(":")
            tmp[0] = tmp[0].upper() + ":"
            line = f"{tmp[0]:30}{tmp[1]}"
        
        # Indention by 2 spaces if there is no key
        else:
            line = "  " + line
        
        out += line + "\n"

    print_info(out)
    print_info()


    ########################################################################################
    # Get DNS data
    ########################################################################################
    print_info("DNS:")
    print_info("="*48)
    entries = ["A", "A6", "AAAA", "AFSDB", "ANY", "APL", "AXFR", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME", "CSYNC", "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "GPOS", "HINFO", "HIP", "IPSECKEY", "ISDN", "IXFR", "KEY", "KX", "LOC", "MAILA", "MAILB", "MB", "MD", "MF", "MG", "MINFO", "MR", "MX", "NAPTR", "NONE", "NS", "NSAP", "NSAP-PTR", "NSEC", "NSEC3", "NSEC3PARAM", "NULL", "NXT", "OPT", "PTR", "PX", "RP", "RRSIG", "RT", "SIG", "SOA", "SPF", "SRV", "SSHFP", "TA", "TKEY", "TLSA", "TSIG", "TXT", "UNSPEC", "URI", "WKS", "X25"]

    for entry in entries:
        found = False
        try:
            answers = dns.resolver.query(domain, entry)
            for rdata in answers:
                found = True
                key = entry + ":"
                print_info(f"{key:15} {rdata.to_text()}")
    
        except Exception as e:
            pass
        
        if found:
            print_info()
    
    print_info()
    

    ########################################################################################
    # Get DNS zonetransfer
    ########################################################################################
    print_info("DNS ZONETRANSFER:")
    print_info("="*48)

    ns_servers = []
    ns_answer = dns.resolver.query(domain, 'NS')
    for server in ns_answer:
        print_info(f"[*] FOUND NS: {server}")
        ip_answer = dns.resolver.query(server.target, 'A')

        for ip in ip_answer:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ip), domain))
                for host in zone:
                    print_error(f"[-] FOUND HOST: {host}.{domain}")

            except Exception as e:
                print_found(f"[+] NS {server} REFUSED ZONE TRANSFER")
                continue


    ########################################################################################
    # Banner grabbing - check for Server or other inform. desclosure - e.g.: PHP version
    ########################################################################################
    print_info("HTTP HEADER INFORMATION:")
    print_info("="*48)
    r = session.get(URL)
    for header in r.headers.keys():
        inform_disc_headers = ["Server", "Set-Cookie"]
        sec_headers = ["Strict-Transport-Security", "Cache-Control", "Set-Cookie", "Content-Security-Policy"]
        info_headers = ["Content-Type", "Transfer-Encoding", "Content-Encoding"]

        # Information Disclosure
        for elem in inform_disc_headers:
            if header.lower() == elem.lower():
                if elem == "Set-Cookie" and "httponly" in r.headers[elem].lower():
                    continue
                print_error(f"[-] INFORM. DISCLOSURE: {elem}: {r.headers[elem]}")

        # Secure Settings
        for elem in sec_headers:
            if header.lower() == elem.lower():
                if elem == "Set-Cookie" and not ("httponly" in r.headers[elem].lower() or "secure"  in r.headers[elem].lower()):
                    continue
                print_found(f"[+] SECURITY SETTING:   {elem}: {r.headers[elem]}")
                

        # Other useful informations
        for elem in info_headers:
            if header.lower() == elem.lower():
                print_info(f"[*] INFO:               {elem}: {r.headers[elem]}")
    
    print_info()


    ########################################################################################
    # Get SSL cert subdomain list
    ########################################################################################
    print_info("SUBDOMAINS:")
    print_info("="*48)

    url = f"https://crt.sh/?q={domain}"
    subdomains = set()

    r = session.get(url)
    if r.status_code == 200:
        soup = BeautifulSoup(r.text, features="lxml")
        element_list = soup.find_all('tr')

        for element in element_list[3:]:
            td = element.find_all('td')[5]
            subdom_list = td.encode_contents().decode("utf-8").split("<br/>")
            for subdom in subdom_list:
                subdomains.add(subdom)

        try:
            subdomains.remove(domain)
        except:
            pass

        for subdom in sorted(subdomains):
            print_info(f"[*] SUDOMAIN FOUND: {subdom}")

    else:
        print_error("[-] ERROR - COULD NOT GET SSL CERTIFICATE LIST")



    ########################################################################################
    # Dirbuster for files and folders with OPTIONS request
    # display also allowed options
    ########################################################################################



    ########################################################################################
    # Check headers for DAV and check if PUT or DELETE are allowed
    ########################################################################################



    ########################################################################################
    # Check all comments of a website
    ########################################################################################

