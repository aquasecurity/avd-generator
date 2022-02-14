---
title: ACM - ACM Certificate Validation
aliases: [
	"/cspm/aws/acm/acm-certificate-validation"
]
heading: Misconfiguration
icon: iac
sidebar_category: misconfig
draft: false
shortName: acm-certificate-validation
severity: "unknown"

avd_page_type: defsec_page

remediations:
  - management console

menu:
  misconfig:
    identifier: aws/acm/acm-certificate-validation
    name: ACM Certificate Validation
    parent: aws/acm
---

Misconfiguration > [aws](../../) > [ACM](../) > ACM Certificate Validation

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


