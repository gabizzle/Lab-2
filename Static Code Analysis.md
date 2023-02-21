# Lab 2 - Static Code Analysis
CISC 7050 - PenTest




### Results to VULPY
***Test results:*** \
Issue: [B113:request_without_timeout] \
Requests call without timeout \
Severity: Medium   Confidence: Low \
CWE: CWE-400 (https://cwe.mitre.org/data/definitions/400.html) \
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b113_request_without_timeout.html \
Location: ./bad/api_list.py:10:8 \
9 \
10	&emsp;&emsp; r = requests.get('http://127.0.1.1:5000/api/post/{}'.format(username)) \
11	&emsp;&emsp; if r.status_code != 200:

***Test results:*** \
Issue: [B108:hardcoded_tmp_directory] Probable insecure usage of temp file/directory. \
Severity: Medium   Confidence: Medium \
CWE: CWE-377 (https://cwe.mitre.org/data/definitions/377.html) \
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b108_hardcoded_tmp_directory.html \
Location: ./bad/api_post.py:6:20 \
5 \
6	&emsp;&emsp; api_key_file = Path('/tmp/supersecret.txt') \
7

***Test results:*** \
Issue: [B113:request_without_timeout] Requests call without timeout \
Severity: Medium   Confidence: Low \
CWE: CWE-400 (https://cwe.mitre.org/data/definitions/400.html) \
More Info: https://bandit.readthedocs.io/en/1.7.5/plugins/b113_request_without_timeout.html \
Location: ./bad/api_post.py:16:12 \
15 \
16 	&emsp;&emsp; r = requests.post('http://127.0.1.1:5000/api/key', json={'username':username, '	password':password}) \
17
