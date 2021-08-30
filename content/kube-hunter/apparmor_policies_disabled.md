---
title: AppArmor Policies Disabled
description: AppArmor policies disabled
types: [Remote Code Execution]

display_title: AppArmor policies disabled
avd_page_type: cloudsploit_page

breadcrumb_remediation_parent: aws
breadcrumb_remediation_parent_name: AWS
breadcrumb_remediation_child: acm
breadcrumb_remediation_child_name: ACM


recommended:
  enable: true
  text: info
  desc: Recommended Severity


---

### Quick Info

| Issue ID | KSV001 |
|-|-|
| **Description** | Sharing the host’s PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration. |
| **Recommended Actions** | Do not set ‘spec.template.spec.hostPID’ to true. |
| **References** | - kubelet server code - Kubelet - options |


## Rego Policy

bla bla bla bla bla bla bla bla bla
bla bla bla bla bla bla bla bla bla
bla bla bla bla bla bla bla bla bla
bla bla bla bla bla bla bla bla bla
bla bla bla bla bla bla bla bla bla