---
title: Insecure Ciphers
draft: false
avd_page_type: cloudsploit_page
---
### Quick Info

| | |
|-|-|
| **Plugin Title** | Insecure Ciphers |
| **Cloud** | AWS |
| **Category** | ELB |
| **Description** | Detect use of insecure ciphers on ELBs |
| **More Info** | Various security vulnerabilities have rendered several ciphers insecure. Only the recommended ciphers should be used. |
| **AWS Link** | http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html |
| **Recommended Action** | Update your ELBs to use the recommended cipher suites |

## Detailed Remediation Steps
1. Log into the AWS Management Console.
2. Select the "Services" option and search for EC2. \
![](/resources/aws/elb/insecure-ciphers/step2.png)
3. In the "EC2 Dashboard" scroll down and look for "Load Balancers" and click on "Load Balancers" to get into "Load Balancers" dashboard.\
![](/resources/aws/elb/insecure-ciphers/step3.png)
4. Select the "Load Balancer" which needs to be verified. \
![](/resources/aws/elb/insecure-ciphers/step4.png)
5. Select the "Listeners" tab from the bottom panel and scroll down to the "Cipher" column of HTTPS Listener and click on "Change" option.\
![](/resources/aws/elb/insecure-ciphers/step5.png)
6. From "Select a Cipher" panel select either of "Predefined Security Policy" and "Custom Security Policy".\
![](/resources/aws/elb/insecure-ciphers/step6.png)
7. Scan the "SSL Cipher Section" from selected "Security Policy" for any insecure ciphers. Refer to the link for all secure ciphers. https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html#ssl-ciphers \
![](/resources/aws/elb/insecure-ciphers/step7.png)
8. Scroll down and click on "Save" button to make the changes. \
![](/resources/aws/elb/insecure-ciphers/step8.png)