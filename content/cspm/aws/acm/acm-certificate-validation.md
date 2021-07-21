---
title: ACM-Certificate-Validation
draft: false

display_title: ACM Certificate Validation
avd_page_type: cloudsploit_page

breadcrumb_remediation_parent: aws
breadcrumb_remediation_parent_name: AWS
breadcrumb_remediation_child: acm
breadcrumb_remediation_child_name: ACM
---
### Quick Info

| Issue ID | AZU001 |
|-|-|
| **Plugin Title** | ACM Certificate Validation |
| **Cloud** | AWS |
| **Category** | ACM |
| **Description** | ACM certificates should be configured to use DNS validation. |
| **More Info** | With DNS validation, ACM will automatically renew certificates before they expire, as long as the DNS CNAME record is in place. |
| **AWS Link** | https://aws.amazon.com/blogs/security/easier-certificate-validation-using-dns-with-aws-certificate-manager/ |
| **Recommended Action** | Configure ACM managed certificates to use DNS validation. |

## Detailed Remediation Steps




