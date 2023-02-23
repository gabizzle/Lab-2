# The code above is an example of a tool that can search a webpage for email addresses. This code is an example of an OSINT tool that can search a webpage for email addresses using regular expressions.
# Here's a brief description of what the code is doing:
# Importing the requests and re modules, which are used to send HTTP requests and search for patterns in text, respectively.
# Setting the url variable to the website you want to search for email addresses.
# Sending a GET request to the specified URL using the requests.get() method, which returns a Response object.
# Searching the HTML content of the Response object for email addresses using the re.findall() method, which uses a regular expression to match email address patterns in the text.
# Printing out the email addresses found on the page using a for loop and the print() function.

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
