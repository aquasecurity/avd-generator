---
title: Authentication and Authorization
id: 3.1
source: Kube Bench
icon: kubernetes
draft: false
shortName: Authentication and Authorization
severity: "n/a"
version: ack-1.0
category: compliance
keywords: "controlplane"

breadcrumbs: 
  - name: Compliance
    path: /compliance
  - name: Kubernetes
    path: /compliance/kubernetes
  - name: CIS - ACK 1.0
    path: /compliance/kubernetes/ack-1.0
  - name: Control Plane Configuration
    path: /compliance/kubernetes/ack-1.0/ack-1.0-controlplane


avd_page_type: avd_page

---

### 3.1 Authentication and Authorization

#### 3.1.1 Revoke client certificate when possible leakage (Manual)

##### Recommended Action
Kubernetes provides the option to use client certificates for user authentication.
ACK issues kubeconfig with its client certificates as the user credentials for connecing to target cluster.
User should revoke his/her issued kubeconfig when possible leakage.

<br />


