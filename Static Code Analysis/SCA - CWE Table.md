# Static Code Analysis CWE

| CWE  | Description | Number of Times it Appeared |
| ------------- | ------------- | ------------- |
| 78 | The product constructs all or part of an OS command using externally influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component. |
| 89 | The product constructs all or part of an SQL command using externally influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. |
| 94 | The product constructs all or part of a code segment using externally influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment. |
| 259 | The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components. A hard-coded password typically leads to a significant authentication failure that can be difficult for the system administrator to detect. Once detected, it can be difficult to fix, so the administrator may be forced into disabling the product entirely. There are two main variations: Inbound: the product contains an authentication mechanism that checks for a hard-coded password. Outbound: the product connects to another system or component, and it contains hard-coded password for connecting to that component. |
| 377 | Creating and using insecure temporary files can leave application and system data vulnerable to attack. |
| 400 | The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources. |
| 703 | The product does not properly anticipate or handle exceptional conditions that rarely occur during normal operation of the product. |
