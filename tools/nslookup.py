import subprocess

def nslookup():
    domain = input("Insert the domain: ")
    result = subprocess.run(['nslookup', domain], capture_output=True, text=True)
    print(result.stdout)