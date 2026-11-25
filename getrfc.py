import requests
import re
import os

# Base URL for IETF RFCs
RFC_BASE_URL = "https://www.rfc-editor.org/rfc/rfc{}.txt"
# RFC 6762 is the latest mDNS specification
# START_RFC = "6762"
START_RFC = "8766"

def get_rfc_text(rfc_number):
    """Downloads the text representation of an RFC."""
    url = RFC_BASE_URL.format(rfc_number.strip())
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    return None

def find_related_rfcs(text):
    """
    Parses the RFC text to find references to other RFCs.
    Look for patterns like 'RFC 1234' or 'RFCs 1234, 5678'.
    """
    pattern = r"RFC\s(\d{4,})"
    related = set(re.findall(pattern, text))
    return related

def main():
    if not os.path.exists("rfcs"):
        os.makedirs("rfcs")

    print(f"Fetching RFC {START_RFC}...")
    root_text = get_rfc_text(START_RFC)
    if not root_text:
        print("Failed to fetch root RFC.")
        return

    with open(f"rfcs/rfc{START_RFC}.txt", "w") as f:
        f.write(root_text)

    related = find_related_rfcs(root_text)
    
    for rfc in related:
        if rfc == START_RFC:
            continue
        print(f"Fetching related RFC {rfc}...")
        text = get_rfc_text(rfc)
        if text:
            with open(f"rfcs/rfc{rfc}.txt", "w") as f:
                f.write(text)

if __name__ == "__main__":
    main()