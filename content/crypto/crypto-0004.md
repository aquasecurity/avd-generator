---
title: "CRYPTO-0004: Expired certificate"
id: CRYPTO-0004
aliases:
  - /crypto/CRYPTO-0004
source: Trivy
icon: aqua
severity: medium
category: crypto
draft: false
summary: An X.509 certificate's notAfter timestamp is earlier than the time Trivy evaluates the findings.
keywords: "CRYPTO-0004, certificate, expiry, expiration, notAfter"
breadcrumbs:
  - name: Cryptography
    path: /crypto
avd_page_type: avd_page
---

## What is checked

Trivy reports an X.509 certificate whose expiry timestamp, `notAfter`, is **before the time the findings are evaluated**. The comparison uses the full timestamp, not just its calendar date.

The default severity is **MEDIUM**.

## Why it matters

Clients that require a currently valid certificate can reject an expired certificate, causing failed connections or other service disruptions. An expired certificate found in an image may also be an unused copy, so review where it is deployed before deciding on remediation.

## Recommended actions

- Renew or replace application certificates and deploy the replacements wherever the old certificates are used.
- Check that applications load the replacements, and reload or restart services where required.
- For certificates supplied by a base image or operating system package, review supplier updates. Remove obsolete certificates only after checking their remaining uses and trust-store requirements.
- Automate renewal and monitor expiry to replace certificates before they expire.

## Scope and limitations

The check covers certificates in system trust stores as well as application files. It does not establish whether an application uses or trusts a certificate.

Certificates with an unknown expiry timestamp do not produce a finding. This rule does not report certificates that are merely close to expiry, check the `notBefore` timestamp, or perform revocation or certificate-chain validation. Its result can change as time passes even when the scanned image is unchanged.

## References

- [RFC 5280, Section 4.1.2.5: Certificate Validity](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5)
- [RFC 5280, Section 6.1: Basic Path Validation](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1)
