#

import requests
import re

# Set up the URL of the website to search for email addresses
url = "https://www.example.com"

# Send a GET request to the URL and search for email addresses using regular expressions
response = requests.get(url)
emails = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", response.text)

# Print out the email addresses found on the page
for email in emails:
    print(f"Email: {email}")
