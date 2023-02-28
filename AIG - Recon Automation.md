# 🤖 Recon Automation 2

```ruby
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

## Explanation
This code focuses on searching for email addresses on a website.

```ruby
response = requests.get(url)
```
This part sends a GET request to the URL using the **_requests_** module and saves the response in the **_response_** variable.
```ruby
emails = re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", response.text)
```
The expression here it used to search for email addresses in the HTML text of the response. The expression looks for strings that match the format of an email address (alphanumeric characters, dots, and special characters like "+"). The pattern checks that the email address ends with a valid top-level domain (TLD) like ".com" or ".org".*

The **_re.findall()_** method finds all occurrences of the pattern in the HTML text and returns them as a list of strings, which is saved in the **_emails_** variable.
```ruby
for email in emails:
    print(f"Email: {email}")
```
This prints the result (email) that it finds with **Email:** in the output.
