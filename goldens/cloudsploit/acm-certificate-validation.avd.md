---
title: ACM Certificate Validation
id: acm-certificate-validation
aliases: [
	"/cspm/aws/acm/acm-certificate-validation"
]
source: CloudSploit
icon: aws
draft: false
shortName: acm-certificate-validation
severity: "unknown"
category: misconfig
keywords: "aws/acm/acm-certificate-validation"

avd_page_type: avd_page

breadcrumbs: 
  - name: AWS
    path: /misconfig/aws
  - name: ACM
    path: /misconfig/aws/acm

remediations:
  - management console

---

### ACM Certificate Validation

ACM certificates should be configured to use DNS validation.

With DNS validation, ACM will automatically renew certificates before they expire, as long as the DNS CNAME record is in place.

### Recommended Actions

Follow the appropriate remediation steps below to resolve the issue.
{{< tabs groupId="remediation" >}}
{{% tab name="Management Console" %}}
1. Log into the AWS console and navigate to the ACM service page.![Step](/path/to/some/image.png)

2. Click into each certificate that has been requested. ![Step](/path/to/some/image.png)

3. Expand the domains associated with the certificate.
4. Ensure each domain listed has DNS validation configured. If DNS validation is used, DNS records will be listed for the domain.
5. Ensure that the records provided by AWS are configured and valid within your DNS provider (such as Route 53).
6. If DNS validation is not used, request a new certificate for the same domains using DNS validation and update the downstream services to use this new certificate. Once done, delete the old certificate to ensure it can no longer be used.{{% /tab %}}
{{< /tabs >}}



### Links
  - https://aws.amazon.com/blogs/security/easier-certificate-validation-using-dns-with-aws-certificate-manager/


