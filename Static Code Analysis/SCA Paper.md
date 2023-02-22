# 📝 Report

[Lets Be Bad Guys Results](https://github.com/gabizzle/Lab-2/blob/a337124fb944f47ebaa7bda53e837769926d6d59/Static%20Code%20Analysis/SCA%20Results%20-%20Bad%20Guys.md) <br>
[Vulpy Results](https://github.com/gabizzle/Lab-2/blob/a337124fb944f47ebaa7bda53e837769926d6d59/Static%20Code%20Analysis/SCA%20Results%20-%20Vulpy.md)

## Summary

&emsp;&emsp;&emsp; The report will discuss two GitHub repositories: **_vulpy_** and **_lets-be-bad-guys_**, with applications and codes with errors and vulnerabilities in them. Using the Bandit tool, the task is to observe and analyze the results and what their mistakes entail. The basis of the explanations of the errors will come from the Common Weakness Enumeration (CWE), which they define as "a community-developed list of common software and hardware weakness types that have security ramifications." The CWE describes "weakness" as "a condition in a software, firmware, hardware, or service component that, under certain circumstances, could contribute to the introduction of vulnerabilities. The CWE List and associated classification taxonomy serve as a language that can be used to identify and describe these weaknesses in terms of CWEs." The CWE will help explain some of the syntax that will appear below. 

| CWE  | Description | Number of Times it Appeared |
| ------------- | ------------- | ------------- |
| 78 | The product constructs all or part of an OS command using externally influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component. | 4 |
| 89 | The product constructs all or part of an SQL command using externally influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. | 6 |
| 94 | The product constructs all or part of a code segment using externally influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment. | 4 |
| 259 | The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. A hard-coded password typically leads to a significant authentication failure that can be difficult for the system administrator to detect. Once detected, it can be difficult to fix, so the administrator may be forced into disabling the product entirely. There are two main variations: Inbound: the product contains an authentication mechanism that checks for a hard-coded password. Outbound: the product connects to another system or component, and it contains hard-coded password for connecting to that component. | 5 |
| 377 | Creating and using insecure temporary files can leave application and system data vulnerable to attack. | 24 |
| 400 | The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources. | 7 |
| 703 | The product does not properly anticipate or handle exceptional conditions that rarely occur during normal operation of the product. | 5 |

&emsp;&emsp;&emsp; Each CWE is accompanied by a "severity" and "confidence" indication which can help determine the priority levels of the impact of the security issue. **Severity** refers to the potential impact of an issue if it were to be exploited. Issues with high severity could lead to significant security breaches, while those with low severity may have minimal impact. **Confidence** refers to the tool's certainty in its detection of an issue. Issues with high confidence are more likely to be genuine security risks, while those with low confidence may be false positives. Having these indications will help developers prioritize which issues to tackle first.

**_Due to the length of the results from both repositories, the results presented in this paper are categorized by each CWE. The rest of the results are linked here: [Lets Be Bad Guys](https://github.com/gabizzle/Lab-2/blob/a337124fb944f47ebaa7bda53e837769926d6d59/Static%20Code%20Analysis/SCA%20Results%20-%20Bad%20Guys.md) and here: [Vulpy](https://github.com/gabizzle/Lab-2/blob/a337124fb944f47ebaa7bda53e837769926d6d59/Static%20Code%20Analysis/SCA%20Results%20-%20Vulpy.md)._**

## Vulpy Results

**Example of CWE-400**
```
Issue: [B113:request_without_timeout] Requests call without timeout
Severity: Medium   Confidence: Low
CWE: CWE-400 (https://cwe.mitre.org/data/definitions/400.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b113_request_without_timeout.html
Location: ./good/httpbrute.py:22:15
21	for password in passwords:
22	response = requests.post(URL, data = {'username': username, 'password': password})
23	if 'HOME' in response.text:
```
**📣 Explanation:** The result shows a warning about a possible security issue in some lines of the code where the requests library *requests.post* is used to make an HTTP POST request without a timeout parameter. This means that having no timeout will make the request wait indefinitely. It can cause the program to become unresponsive - to hang or have an unstable connection. Therefore, attackers can use this to launch a Denial of Service (DoS) attack to make it completely unresponsive and unusable.

**☑️ Possible Solution:** A reasonable timeout value in the request can be added. This allows the application to wait for a response for a certain amount of time before giving up. This ensures that the application remains responsive and prevents a DoS attack.

**Example of CWE-377**
```
Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
Severity: Medium   Confidence: Medium
CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b108_hardcoded_tmp_directory.html
Location: ./bad/libapi.py:20:14
19
20	keyfile = '/tmp/vulpy.apikey.{}.{}'.format(username, key)
21
```
**📣 Explanation:** The result is pointing out that an API key is hardcoded in a temporary *'/tmp/'* directory path. This means that the code is relying on the /tmp/ directory to store sensitive information (in this case, an API key) without considering the possible security implications. This is a public directory where any user can write or read files. It becomes possible for an attacker to guess the file name and access sensitive information stored in this directory. 

**☑️ Possible Solution:** The best practice is to use a secure and unique temporary directory and ensure that the file is only accessible by the owner of the file. Temporary files or directories are commonly used by applications to store intermediate or temporary data, such as session information or file uploads. However, it is generally considered bad practice to use hardcoded paths for temporary files or directories because it can lead to vulnerabilities. If hardcoded temporary directory is writable by anyone, it could be used by attackers to execute malicious code or to store malware. It is recommended to use a secure and unique temporary directory and set proper access permissions to prevent unauthorized access or modification.

**Example of CWE-259**
```
Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'aaaaaaa'
Severity: Low   Confidence: Medium
CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b105_hardcoded_password_string.html
Location: ./good/vulpy-ssl.py:13:11
12	app = Flask('vulpy')
13	app.config['SECRET_KEY'] = 'aaaaaaa'
14
```
**📣 Explanation:** The result warns that there is a hardcoded password in the code. In this case it is 'aaaaaaa', which also shows poor security practices. Hardcoded passwords are risky, and passwords that don't have a uniqueness to it can be easily cracked. This can lead to unauthorized access where attackers can exploit their access to systems. Hardcoded passwords also involve modifying the source code and rebuilding the application every time it needs to be changed. It is inefficient and can cause more accidentally modifications.

**☑️ Possible Solution:** It is recommended to use a secure password storage mechanism, such as a password manager or configuration files, instead of hardcoding passwords directly into the source code. This makes it easier to manage and update passwords as needed, without exposing them to potential attackers.

**Example of CWE-94**
```
Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
Severity: High   Confidence: Medium
CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b201_flask_debug_true.html
Location: ./bad/vulpy-ssl.py:29:0
28
29	app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
```
**📣 Explanation:** The result here indicates that a Flask application is being run with the debug mode set to True. When debug mode is enabled, it allows the Werkzeug debugger to be accessed and it also allows the execution of arbitrary code. Debug mode is used for development and testing, and not for production purposes. Werkzeug can expose sensitive information, such as server configuration, environment variables, and stack traces. This poses a security risk because attackers can use the debugger to inspect the application's code and potentially exploit vulnerabilities.

**☑️ Possible Solution:** It is recommended to disable debug mode when deploying Flask applications to production environments. Flask is a flexible web framework for Python used to build web applications. Therefore, it is important to ensure that debug mode is disabled when deploying Flask applications in production environments.

**Example of CWE-89**
```
Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
Severity: Medium   Confidence: Medium
CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b608_hardcoded_sql_expressions.html
Location: ./bad/db_init.py:20:18
19	for u,p in users:
20 	c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%d', '%d', '%s')" %(u, p, 0, 0, ''))
21
```
**📣 Explanation:** The result indicates an SQL injection vulnerability. Specifically, the result "B608: hardcoded_sql_expressions" suggests that the code is building an SQL query by putting together different pieces of text, including some values provided by the user. However, the code does not take steps to protect itself against attacks where someone maliciously enters special characters or commands that can modify or damage the database. This can allow attackers to access sensitive information, modify data, or even take control of the server. 

**☑️ Possible Solution:** To remediate SQL injection, you should use parameterized queries, also known as prepared statements, in your code. Instead of concatenating input values with the SQL query string, you should use placeholders for the input values and pass them as parameters to the query. This separates the query logic from the input values and prevents attackers from injecting malicious SQL code. It is also important to ensure that input values are properly escaped or validated to prevent unintended behavior of the query. By following these practices, you can protect your application from SQL injection attacks.

## Lets-Be-Bad-Guys Results

**Example of CWE-703**
```
Issue: [B110:try_except_pass] Try, Except, Pass detected.
Severity: Low   Confidence: High
CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
Location: ./badguys/vulnerable/views.py:65:8
More Info: https://bandit.readthedocs.io/en/1.7.4/plugins/b110_try_except_pass.html
64	os.unlink('p0wned.txt')
65	except:
66	pass
```
- This result is from a security tool called "Bandit" and it is warning that the code contains a try/except block where the exception is caught but nothing is done with it. This is considered bad practice because it can hide errors and make debugging difficult. In particular, the except block has only a pass statement, which means that if an error occurs, it will be silently ignored and the program will continue to execute as if nothing happened. In this case, the code is attempting to delete a file p0wned.txt, and if an error occurs during the deletion, it will be suppressed by the except block. If there is a problem deleting the file, the program should handle the error in a way that provides feedback to the user and does not continue execution as if everything is okay.
- The issue with using a try-except block with a pass statement in this context is that it silently ignores any errors that may occur. This can lead to unexpected or undefined behavior, as the error is not being properly handled or reported to the user.
- In the specific case of the result you provided, the code attempts to delete a file using os.unlink, which may raise an exception if the file does not exist or if there is a permission error. However, the try-except block with a pass statement causes the exception to be ignored, meaning that if an error occurs, the program will not raise an error or otherwise inform the user that the file could not be deleted.
- This could be potentially problematic if the program relies on the file being deleted, as it may continue to run with incorrect assumptions about the file system. In addition, it could be a security issue if the file being deleted contains sensitive information and the failure to delete the file leaves that information exposed.

**Example of CWE-78**
```
Issue: [B102:exec_used] Use of exec detected.
Severity: Medium   Confidence: High
CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
Location: ./badguys/vulnerable/views.py:72:12
More Info: https://bandit.readthedocs.io/en/1.7.4/plugins/b102_exec_used.html
71	# Try it the Python 3 way...
72	exec(base64.decodestring(bytes(first_name, 'ascii')))
73	except TypeError:
```
**📣 Explanation:** The result shows that a code contains the use of the exec() function, which can execute arbitrary code in the context of the current process. This can be a potential security vulnerability, as it allows an attacker to execute arbitrary code on the system. The severity of this issue is considered medium and the confidence of the detection is high. The specific location of this issue is in the file *./badguys/vulnerable/views.py*, line 72, where the *exec()* function is being used to decode a base64 string.

**☑️ Solution:** - Using exec() is also often an indication of poor design, as it can be a sign that a more secure and maintainable design approach is needed. Therefore, it is important to avoid using exec() and instead find safer alternatives to achieve the same functionality.

## Methodology

## Recommendations
