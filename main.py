from tools.scanner import init_scan
from tools.nslookup import nslookup
from tools.wappalyzer import identify_technologies
from tools.wafwoof import detect_waf
from tools.who_is import run_whois

def showing_tools():
    print("1. Portscan")
    print("2. Nslookup")
    print("3. Wappalyzer")
    print("4. Wafw00f")
    print("5. Whois")

print("Welcome to Recon-Tools! A group of tools for target recognition")

while True:
    showing_tools()
    e = input("Type the number of the tool you want to use: ")

    if e == "1":
        print("Initializing port scanner")
        init_scan()
        print("Ended port-scanner \n")
    elif e == "2":
        print("Initializing Nslookup")
        nslookup()
        print("Ended Nslookup \n")
    elif e == "3":
        print("Initializing Wappalyzer")
        identify_technologies()
        print("Ended Wappalyzer \n")
    elif e == "4":
        print("Initializing Wafw00f")
        detect_waf()
        print("Ended Wafw00f \n")
    elif e == "5":
        print("Initializing Whois")
        run_whois()
        print("Ended Whois \n")
