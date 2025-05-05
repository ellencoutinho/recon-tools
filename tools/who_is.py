import whois

def run_whois(domain):
    info = whois.whois(domain)
    print(f"Domain: {info.domain_name}")
    print(f"Registered by: {info.registrar}")
    print(f"Creation date: {info.creation_date}")
    print(f"Expiration date: {info.expiration_date}")
    print(f"DNS servers: {info.name_servers}")
    print(f"Emails: {info.emails}")
