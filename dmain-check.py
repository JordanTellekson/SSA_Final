import whois
from datetime import datetime

def check_domain(domain):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date

        # sometimes WHOIS returns a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now(creation_date.tzinfo) - creation_date).days

            print(f"Domain: {domain}")
            print(f"Created: {creation_date}")
            print(f"Age: {age_days} days")

            if age_days < 30:
                print("⚠️ Suspicious: Recently registered domain")
            else:
                print("✅ Looks normal")
        else:
            print("Could not determine creation date")

    except Exception as e:
        print("Error checking domain:", e)

# test it
check_domain("google.com")       