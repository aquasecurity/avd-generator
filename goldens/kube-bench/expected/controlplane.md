---
title: Control Plane Configuration
id: 3
source: Kube Bench
icon: kubernetes
draft: false
shortName: Control Plane Configuration
severity: "n/a"
version: ack-1.0
category: misconfig
keywords: "controlplane"

breadcrumbs: 
  - name: Kubernetes
    path: /misconfig/kubernetes
  - name: Benchmarks
    path: /misconfig/kubernetes/benchmarks
  - name: ACK 1.0
    path: /misconfig/kubernetes/benchmarks/ack-1.0

avd_page_type: avd_page

---

### 3 Control Plane Configuration

### 3.1 Authentication and Authorization

#### 3.1.1 Revoke client certificate when possible leakage (Manual)
Kubernetes provides the option to use client certificates for user authentication.
ACK issues kubeconfig with its client certificates as the user credentials for connecing to target cluster.
User should revoke his/her issued kubeconfig when possible leakage.

<br />



### 3.2 Logging

#### 3.2.1 Ensure that a minimal audit policy is created (Manual)
Create an audit policy file for your cluster.

<br />


#### 3.2.2 Ensure that the audit policy covers key security concerns (Manual)
Consider modification of the audit policy in use on the cluster to include these items, at a
minimum.

<br />



