import re
import sys
import whois
import requests
import subprocess

import dns.zone
import dns.resolver

from bs4 import Comment
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

########################################################################################
# Functions for output and logging
########################################################################################

def usage():
    print("\nUSAGE:")
    print("=======================")
    print("war.py [URL] [DIR/FILE WORDLIST] [DNS WORDLIST]\n")
    print("e.g.: \nwar.py https://web.site /usr/share/wordlists/dirb/common.txt\n")
    quit()

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

def ansi_escape(txt):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', txt)


########################################################################################
# CLI args processing
########################################################################################

# Check if 3 arguments are given and print usage if not
# Check for -h or --help in arguments
if len(sys.argv) != 4 or "-h" in sys.argv or "--help" in sys.argv:
    usage()


# Set URL and WORDLIST to the according values
URL = sys.argv[1]
WORDLIST = sys.argv[2]
DNS_WORDLIST = sys.argv[3]

# Testing values
#URL = "http://192.168.1.2"
#WORDLIST = "common.txt"
#DNS_WORDLIST = "dns.txt"


# Check if wordlists are readable and display error if not
try:
    # Read wordlist
    with open(WORDLIST, "r") as f:
        wordlist = f.read().split("\n")

except Exception as e:
    print(e)
    quit()

try:
    # Read DNS wordlist
    with open(DNS_WORDLIST, "r") as f:
        dns_wordlist = f.read().split("\n")

except Exception as e:
    print(e)
    quit()


EXTS = "zip,bz2,tar,gz,tgz,tar.bz2,tar.gz,old,bak,inc,ini,xml,txt,yaml,yml,conf,cnf,config,json,local,pub,sql,mysql,pgsql,mdb,sqlite,sqlite2,sqlite3,db,mf,md,passwd,reg,readme,log,LOG,asa,asax,backend,wadl,1".split(",")
CODE_EXTS = "php,html,htm,asp,py,pl,cgi,cfm".split(",")


########################################################################################
# Setup Requests session
########################################################################################
session = requests.Session()
session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'})


########################################################################################
# LOG OUTPUT
########################################################################################
domain = URL.split("/")[2].lower()
schema = URL.split("//")[0].lower()
subdomain_list = set()
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
                print_info(f"[*] FOUND IP: {key:15} {rdata.to_text()}")
    
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

    zonetransfer_failed = True
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
                    subdomain_list.add(f"{host}.{domain}")
                    zonetransfer_failed = False

            except Exception as e:
                print_found(f"[+] NS {server} REFUSED ZONE TRANSFER")
                continue

    print_info()

    
    ########################################################################################
    # Bruteforce DNS names
    ########################################################################################
    if zonetransfer_failed:
        print_info("DNS BRUTEFORCE:")
        print_info("="*48)
        entries = ["A", "AAAA"]

        for entry in entries:
            for host in dns_wordlist:
                subdom = f"{host}.{domain}"
                print(f"Checking: {subdom:48}", end="\r")
                sys.stdout.flush()

                try:
                    answers = dns.resolver.query(subdom, entry)
                    for rdata in answers:
                        key = entry + ":"
                        print_info(f"[*] FOUND IP: {rdata.to_text()} [{subdom}]")
                        subdomain_list.add(f"{subdom}")
            
                except Exception as e:
                    pass
            
        print(" "*60, end="\r") # Clear last checking output
        print_info()


    ########################################################################################
    # Banner grabbing - check for Server or other inform. desclosure - e.g.: PHP version
    ########################################################################################
    print_info("HTTP HEADER INFORMATION:")
    print_info("="*48)
    r = session.get(URL)
    for header in r.headers.keys():
        inform_disc_headers = ["Server", "Set-Cookie", "X-Powered-By"]
        sec_headers = ["Strict-Transport-Security", "Cache-Control", "Set-Cookie", "Content-Security-Policy"]
        info_headers = ["Content-Type", "Transfer-Encoding", "Content-Encoding", "X-XSS-Protection"]

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
            if "*" not in subdom:
                subdomain_list.add(subdom)

    else:
        print_error("[-] ERROR - COULD NOT GET SSL CERTIFICATE LIST")
    
    print_info()


    ########################################################################################
    # Using whatweb to get the techn. stack
    ########################################################################################
    print_info("WEB TECHNOLOGIES:")
    print_info("="*48)

    inform_disc_headers = ["Server", "Set-Cookie", "X-Powered-By", "JQuery", "Script", "WordPress", "PoweredBy", "MetaGenerator"]
    sec_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-XSS-Protection", "HttpOnly"]

    try:
        res = subprocess.check_output(["whatweb", domain], stderr=subprocess.STDOUT)
        
        # Find starting point
        lines = res.decode("UTF-8").strip().split("\n")
        for i in range(len(lines)):
            if "200 OK" in lines[i]:
                start = i
        
        # Remove warnings and redirection messages
        lines = lines[start:]
        lines = "\n".join(lines)

        # Remove color informations
        lines = ansi_escape(lines)

        # Format output
        lines = lines.split(", ")
        print_info(lines[0])
        for line in lines[1:]:
            try:
                for entry in inform_disc_headers:
                    if entry.lower() in line.lower():
                        print_error("  [-] " + line.replace("[", ": ").replace("]", ""))
                        raise(IndexError)

                for entry in sec_headers:
                    if entry.lower() in line.lower():
                        print_found("  [+] " + line.replace("[", ": ").replace("]", ""))
                        raise(IndexError)

            except IndexError:
                continue
            
            print_info("  [*] " + line.replace("[", ": ").replace("]", ""))

    except FileNotFoundError:
        print_error("[-] whatweb NOT INSTALLED")

    print_info()

    ########################################################################################
    # Check which subdomains have a webserver running
    ########################################################################################
    print_info("CHECKING SUBDOMAINS FOR RUNNING WEBSERVERS:")
    print_info("="*48)

    no_http = []
    for subdom in subdomain_list:
        print(f"Checking: {subdom:48}", end="\r")
        sys.stdout.flush()

        url = f"http://{subdom}"
        try:
            r = requests.get(url, timeout=3)
            print_info(f"[*] WEBSERVER FOUND: {url} [Status-Code: {r.status_code}]")
        except (requests.exceptions.ConnectionError, requests.exceptions.InvalidURL) as e:
            no_http.append(subdom)

    # clean list
    for subdom in no_http:
        subdomain_list.remove(subdom)
    
    # Prepare list for next step
    del(no_http)
    subdomain_list = [domain,] + list(sorted(subdomain_list))
    if f"www.{domain}" in subdomain_list:
        subdomain_list.remove(f"www.{domain}")

    print(" "*60, end="\r") # Clear last checking output
    print_info()


    ########################################################################################
    # Utilize wafw00f
    ########################################################################################
    print_info("WAFW00F:")
    print_info("="*48)
    
    try:
        res = subprocess.check_output(["wafw00f", "-a", domain], stderr=subprocess.STDOUT)
        lines = res.decode("UTF-8")

        # Remove color informations
        lines = ansi_escape(lines)

        print_info(lines)
    except FileNotFoundError:
        print_error("[-] wafw00f NOT INSTALLED")
    
    print_info()


    ########################################################################################
    # Utilize nmap
    ########################################################################################
    print_info("NMAP:")
    print_info("="*48)
    
    try:
        res = subprocess.check_output(["nmap", "-sV", "-sC", domain], stderr=subprocess.STDOUT)
        lines = res.decode("UTF-8")

        # Remove color informations
        lines = ansi_escape(lines)

        print_info(lines)
    except FileNotFoundError:
        print_error("[-] nmap NOT INSTALLED")
    
    print_info()


    ########################################################################################
    # Output robots.txt
    ########################################################################################
    print_info("ROBOTS.TXT:")
    print_info("="*48)
    
    try:
        url = f"{schema}//{domain}/robots.txt"
        r = session.get(url)
        print_info(r.text)
    except:
        print_info("[*] robots.txt NOT FOUND")
    
    print_info()


    ########################################################################################
    # Dirbuster for files and folders with OPTIONS request
    # display also allowed options
    ########################################################################################
    def dirb(base_url, indent=0):
        global wordlist
        global EXTS
        global CODE_EXTS

        # Check folders
        for word in wordlist:
            print(f"Checking: {word:48}", end="\r")
            sys.stdout.flush()

            url = f"{base_url}{word}"
            r = session.head(url)
            if r.status_code == 200:
                r2 = session.options(url)
                
                # Listable directories
                try:
                    print_error(" "*indent + f"[-] FOUND FOLDER: {url} [Status-Code: {r.status_code}] [Allow: {r2.headers['Allow']}]")
                except KeyError:
                    print_error(" "*indent + f"[-] FOUND FOLDER: {url} [Status-Code: {r.status_code}]")

            elif r.status_code != 404:
                r2 = session.options(url)
                # Check for WebDAV
                wd = ""
                if "DAV" in r2.headers.keys():
                    wd = f", WebDAV: {r.headers['DAV']}"

                # Check other HTTP methods
                try:
                    # Check for PUT or DELETE method
                    if "PUT" in r2.headers['Allow'] or "DELETE" in r2.headers['Allow']:
                        print_error(" "*indent + f"[-] FOUND FOLDER: {url} [Status-Code: {r.status_code}] [Allow: {r2.headers['Allow']}{wd}]")

                    # All other HTTP-methods
                    else:
                        print_info(" "*indent + f"[*] FOUND FOLDER: {url} [Status-Code: {r.status_code}] [Allow: {r2.headers['Allow']}{wd}]")

                # No OPTIONS found in headers
                except KeyError:
                    print_info(" "*indent + f"[*] FOUND FOLDER: {url} [Status-Code: {r.status_code}]")

                # Check subfolder
                if word != "":
                    dirb(f"{base_url}{word}/", indent=indent+4)


            # Check files that could leak information
            for ext in EXTS:
                url = f"{base_url}{word}.{ext}"
                r = session.head(url)
                
                # Skip .hta.*, .htaccess.*, .htpasswd.* because most servers will give you a 
                # 403 error for each file-extention in combination with this 3 filenames
                if r.status_code == 403 and word in [".hta", ".htaccess", ".htpasswd"]:
                    continue

                # If response is not "file not found error" show found file
                if r.status_code != 404:
                    print_error(" "*indent + f"[-] FOUND FILE:   {url} [Status-Code: {r.status_code}]")


            ########################################################################################
            # Check all HTML comments of a website
            ########################################################################################
            for ext in CODE_EXTS:
                url = f"{base_url}{word}.{ext}"
                r = session.get(url)
                if r.status_code == 200:
                    print_info(" "*indent + f"[*] FOUND FILE:   {url} [Status-Code: {r.status_code}]")
                    
                    # Parse HTML and find comments
                    soup = BeautifulSoup(r.text, 'html.parser')
                    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
                    for c in comments:
                        for line in c.split("\n"):
                            print_error(" "*indent + f"    Comment: {line.strip()}")

        print(" "*60, end="\r") # Clear last checking output

    # Run check
    for subdom in subdomain_list:
        base_url = f"{schema}//{subdom}/"

        print_info(f"CHECKING FILES/FOLDERS IN {base_url}:")
        print_info("="*48)

        dirb(base_url)
        
        print_info()
