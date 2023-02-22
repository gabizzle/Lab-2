# Recon Automation 2

```
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
```

This code is an example of an OSINT tool that can search a webpage for email addresses using regular expressions.

Here's a brief description of what the code is doing:

1.  Importing the requests and re modules, which are used to send HTTP requests and search for patterns in text, respectively.
2.  Setting the url variable to the website you want to search for email addresses.
3.  Sending a GET request to the specified URL using the requests.get() method, which returns a Response object.
4.  Searching the HTML content of the Response object for email addresses using the re.findall() method, which uses a regular expression to match email address patterns in the text.
5.  Printing out the email addresses found on the page using a for loop and the print() function.
6.  This code can be modified to search for other patterns or data types on a webpage, such as phone numbers, addresses, or names, by changing the regular expression used in re.findall(). However, it's worth noting that some websites may have protections in place to prevent web scraping, so it's important to make sure that your use of this code is legal and ethical.
