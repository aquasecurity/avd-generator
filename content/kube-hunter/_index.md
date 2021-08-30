---
title: "Kubehunter"
draft: false
weight: 1
avd_page_type: cloudsploit_page
---


## Security Issues: 
### PSP
- [AppArmor policies disabled](/kube-hunter/apparmor_policies_disabled/)
- Can elevate its own privileges
- Default capabilities
- SYS_ADMIN capability added
- hostPath volume mounted with docker.sock


### General

- Manages -etc-hosts
- Access to host IPC namespace
- Access to host network
- Access to host PID
- Disable kublet debugging handler
- Restrict Azure AKS CIDR
