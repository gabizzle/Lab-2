# Results to Lets Be Bad Guys


***Test results:***
```ruby
Issue: [B110:try_except_pass] Try, Except, Pass detected.
Severity: Low   Confidence: High
CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
Location: ./badguys/vulnerable/views.py:65:8
More Info: https://bandit.readthedocs.io/en/1.7.4/plugins/b110_try_except_pass.html
64      os.unlink('p0wned.txt')
65      except:
66      pass
```

***Test results:***
```ruby
Issue: [B102:exec_used] Use of exec detected.
Severity: Medium   Confidence: High
CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
Location: ./badguys/vulnerable/views.py:72:12
More Info: https://bandit.readthedocs.io/en/1.7.4/plugins/b102_exec_used.html
71       # Try it the Python 3 way...
72       exec(base64.decodestring(bytes(first_name, 'ascii')))
73       except TypeError:
```

***Test results:***
```ruby
Issue: [B102:exec_used] Use of exec detected.
Severity: Medium   Confidence: High
CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
Location: ./badguys/vulnerable/views.py:76:16
More Info: https://bandit.readthedocs.io/en/1.7.4/plugins/b102_exec_used.html
75        try:
76        exec(base64.decodestring(first_name))
77        except:
```

***Test results:***
```ruby
Issue: [B110:try_except_pass] Try, Except, Pass detected.
Severity: Low   Confidence: High
CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
Location: ./badguys/vulnerable/views.py:77:12
More Info: https://bandit.readthedocs.io/en/1.7.4/plugins/b110_try_except_pass.html
76        exec(base64.decodestring(first_name))
77	      except:
78        pass
```

***Test results:***
```ruby
Issue: [B110:try_except_pass] Try, Except, Pass detected.
Severity: Low   Confidence: High
CWE: CWE-703 (https://cwe.mitre.org/data/definitions/703.html)
Location: ./badguys/vulnerable/views.py:79:8
More Info: https://bandit.readthedocs.io/en/1.7.4/plugins/b110_try_except_pass.html
78        pass
79        except:
80        pass
```
