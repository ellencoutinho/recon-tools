import subprocess

def detect_waf():
    url = input("Insert the url to describe if there is WAF: ")
    result = subprocess.run(['wafw00f', url], capture_output=True, text=True)
    print(result.stdout)
