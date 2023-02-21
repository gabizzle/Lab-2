# Static Code Analysis

### Example for CWE-703
```
Issue: [B110:try_except_pass] Try, Except, Pass detected.
Severity: Low   Confidence: High
CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b110_try_except_pass.html
Location: ./bad/libsession.py:21:4
20        session = json.loads(base64.b64decode(cookie))
21        except Exception:
22        pass
23
```
- This result is from a static code analysis tool called Bandit. It indicates that a try/except block with a pass statement was detected in the file libsession.py on line 21, column 4.
- The try/except block is used to handle exceptions that may occur while executing the code within the block. However, in this case, the pass statement within the except block effectively does nothing and ignores any exception that might be raised. This can hide potential issues in the code and make it more difficult to identify and resolve problems.
- The severity of the issue is labeled as "Low", which means that the issue may not necessarily pose a significant security risk, but it may still impact the performance or functionality of the system. The confidence level of the tool's analysis is "High", which means that the issue is almost certainly present and can be easily confirmed.
- The issue is mapped to a specific Common Weakness Enumeration (CWE) number, which provides a standardized way of identifying and categorizing software weaknesses. In this case, the CWE number is 703, which is related to the use of improper exception handling.
- Finally, the output provides a link to the Bandit documentation, which provides more information about the specific issue (B110) and how it can be resolved. To resolve this issue, the try/except block should be updated to handle the exception in a more appropriate manner, such as logging the error or providing a more informative error message. Alternatively, if the exception is not important for the application's functionality, the try/except block can be removed altogether.

### Example for CWE-400
```
Issue: [B113:request_without_timeout] Requests call without timeout
Severity: Medium   Confidence: Low
CWE: CWE-400 (https://cwe.mitre.org/data/definitions/400.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b113_request_without_timeout.html
Location: ./bad/api_list.py:10:8
9
10        r = requests.get('http://127.0.1.1:5000/api/post/{}'.format(username))
11        if r.status_code != 200:
```
- This result is from a static code analysis tool called Bandit. It indicates that in the file api_post.py, a requests.post call is made without a timeout parameter, which could potentially cause the program to hang or become unresponsive if the server does not respond in a timely manner.
- The severity of the issue is labeled as "Medium", which means that it could potentially cause a security vulnerability or impact system stability. The confidence level of the tool's analysis is "Low", which means that further investigation may be needed to confirm the issue.
- The issue is mapped to a specific Common Weakness Enumeration (CWE) number, which provides a standardized way of identifying and categorizing software weaknesses. In this case, the CWE number is 400, which is related to the lack of robustness in error handling or failure to gracefully handle unexpected conditions.
- The output provides a link to the Bandit documentation, which provides more information about the specific issue (B113) and how it can be resolved. To address this issue, the requests.post call should be modified to include a timeout parameter, which specifies the maximum amount of time to wait for a response from the server before raising an exception or returning an error. This helps ensure that the program remains responsive and does not hang or become unresponsive if the server does not respond in a timely manner.


### Example for CWE-377
```
Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory.
Severity: Medium   Confidence: Medium
CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b108_hardcoded_tmp_directory.html
Location: ./bad/libapi.py:16:18
15
16        for f in Path('/tmp/').glob('vulpy.apikey.' + username + '.*'):
17        print('removing', f)
```
- This result means that the code is probably using a hardcoded temporary file directory (/tmp/) for storing files related to the vulpy.apikey and the directory permissions might not be set up securely. It's important to note that /tmp/ is a common target for attackers as it is usually world-readable and writable, and thus provides an easy way for attackers to manipulate files and execute code on the system.
- The glob() function call in the code sample suggests that the code is iterating over the files matching a certain pattern in the /tmp/ directory, and removing them. If the username value comes from an untrusted source, an attacker may be able to perform directory traversal attacks by crafting a malicious input that manipulates the username value and accesses arbitrary files outside of the expected directory. To avoid this, it's recommended to use a more secure temporary file directory with restricted permissions or to generate a unique, unpredictable temporary file name.

### Example for CWE-259
```
Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'aaaaaaa'
Severity: Low   Confidence: Medium
CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b105_hardcoded_password_string.html
Location: ./bad/vulpy-ssl.py:13:11
12        app = Flask('vulpy')
13        app.config['SECRET_KEY'] = 'aaaaaaa'
14
```
- This result is from a static code analysis tool called Bandit. It indicates that a possible hardcoded password string was found in a file called vulpy-ssl.py on line 13, column 11. The value of the hardcoded password string is aaaaaaa.
- The severity of the issue is labeled as "Low" and the confidence level of the tool's analysis is "Medium". This means that while the issue has the potential to be a security vulnerability, it may not necessarily be exploitable in practice. Further investigation is needed to determine the impact of the issue on the security of the system.
- The issue is mapped to a specific Common Weakness Enumeration (CWE) number, which provides a standardized way of identifying and categorizing security vulnerabilities. In this case, the CWE number is 259, which is related to the use of hard-coded credentials.
- Finally, the output provides a link to the Bandit documentation, which provides more information about the specific issue (B105) and how it can be resolved. To resolve this issue, the hardcoded password should be removed or replaced with a more secure solution such as a randomly generated secret or an environment variable.
- The problem with a hardcoded password string, such as the one identified by Bandit in this result, is that it is a security vulnerability that could allow an attacker to gain unauthorized access to the system. Hardcoded passwords are easy to discover and exploit, and they can be a common attack vector for malicious actors.
- If an attacker gains access to the hardcoded password, they could use it to impersonate a legitimate user and gain unauthorized access to sensitive data or system resources. Additionally, if the password is used in multiple places, an attacker could use the same password to gain access to other parts of the system.
- To mitigate this vulnerability, the hardcoded password should be removed or replaced with a more secure solution such as a randomly generated secret or an environment variable. This makes it much harder for an attacker to discover the password and gain unauthorized access to the system.

### Example for CWE-94
```
Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
Severity: High   Confidence: Medium
CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b201_flask_debug_true.html
Location: ./good/vulpy.py:53:0
52
53        app.run(debug=True, host='127.0.1.1', port=5001, extra_files='csp.txt')
54
```
- This result is from a static code analysis tool called Bandit. It indicates that the Flask application in the file vulpy.py appears to be running with the debug=True setting, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
- When Flask is run with debug mode enabled, Werkzeug provides a built-in debugger that allows developers to interactively debug their applications. However, this mode is not intended for use in production environments and can expose sensitive information and vulnerabilities.
- The severity of the issue is labeled as "High", which means that the issue poses a significant security risk that could be exploited by attackers. The confidence level of the tool's analysis is "Medium", which means that while the issue is likely present, further investigation may be needed to confirm it.
- The issue is mapped to a specific Common Weakness Enumeration (CWE) number, which provides a standardized way of identifying and categorizing software weaknesses. In this case, the CWE number is 94, which is related to allowing an attacker to execute arbitrary code.
- Finally, the output provides a link to the Bandit documentation, which provides more information about the specific issue (B201) and how it can be resolved. To resolve this issue, the debug parameter should be set to False before deploying the Flask application in a production environment.

### Example for CWE-89
```
Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
Severity: Medium   Confidence: Medium
CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b608_hardcoded_sql_expressions.html
Location: ./bad/db.py:19:18
18        for u,p in users:
19        c.execute("INSERT INTO users (user, password, failures) VALUES ('%s', '%s', '%d')" %(u, p, 0))
20
```
- This result is a warning about a possible SQL injection vulnerability in the code. The code appears to be constructing SQL queries using string concatenation rather than using parameterized queries, which can make the code vulnerable to SQL injection attacks. An attacker could exploit this vulnerability to execute arbitrary SQL code on the underlying database, potentially leading to data theft or destruction. The severity of this issue is Medium, which means that while it is not as serious as some other security issues, it still needs to be addressed. The confidence level is Medium, which indicates that the analysis is not completely certain that this is a vulnerability, but it is highly likely. The CWE associated with this issue is CWE-89, which is a commonly used identifier for SQL injection vulnerabilities.

### Example for CWE-78
```
Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
Severity: Low   Confidence: High
CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
More Info: https://bandit.readthedocs.io/en/1.7.5/blacklists/blacklist_imports.html#b404-import-subprocess
Location: ./bad/brute.py:3:0
2
3        import subprocess
4         import sys
```
- This result is a warning that the subprocess module is being imported in a file named brute.py. The warning suggests that you should consider the possible security implications associated with using the subprocess module, as it can allow for the execution of arbitrary system commands. The subprocess module is often used to spawn new processes, which can execute system commands. If not used carefully, it can introduce vulnerabilities, such as command injection attacks, which could allow an attacker to execute malicious commands on the system. The warning is just a reminder to ensure that the use of the subprocess module is secure and that the user input is validated before it is passed to the subprocess module.
- This Bandit result is warning about the potential for SQL injection vulnerability in the code. Specifically, the result is labeled as [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction..
- The code snippet in question is using string concatenation to construct an SQL query, which includes variables for the username, password, and a value for a "failures" column. However, this approach is vulnerable to SQL injection attacks, where an attacker can manipulate the data being inserted into the database and potentially execute malicious SQL statements.
- To avoid this risk, it is recommended to use parameterized queries instead of string concatenation when building SQL queries. Parameterized queries use placeholders for values that are then bound to parameters, separating the data from the query itself and preventing SQL injection attacks.
