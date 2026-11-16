---
title: "CRYPTO-0006: MD2, MD4 or MD5 certificate signature"
id: CRYPTO-0006
aliases:
  - /crypto/CRYPTO-0006
source: Trivy
icon: aqua
severity: high
category: crypto
draft: false
summary: An X.509 certificate is signed using MD2, MD4, or MD5, which are obsolete, cryptographically broken hash functions with practical collision attacks.
keywords: "CRYPTO-0006, MD2, MD4, MD5, certificate, signature"
breadcrumbs:
  - name: Cryptography
    path: /crypto
avd_page_type: avd_page
---

## What is checked

Trivy reports an X.509 certificate whose signature algorithm identifies MD2, MD4, or MD5 with RSA. The finding concerns the signature on the certificate, which was created by its issuer. It does not describe the algorithm of the certificate's own public key.

## Impact

MD2, MD4, and MD5 have severe cryptographic weaknesses and practical collision attacks. RFC 6149 and RFC 6150 moved MD2 and MD4 to Historic status, and RFC 6151 details the security considerations regarding MD5 collisions, recommending against its use in digital signatures. Industry standards such as the CA/Browser Forum Baseline Requirements prohibit their use in certificates. An attacker could potentially forge certificates that share the same signature.

## Recommended actions

- Have the issuer reissue application certificates using a secure signature algorithm with SHA-256 or a stronger hash.
- Update certificate authority and infrastructure configurations to prevent issuance of certificates using legacy hash functions.
- For certificates supplied by a base image, operating system package, or third party, review updates from that supplier. Review trust requirements before removing a certificate from a trust store.

## Scope and limitations

Certificates in system trust stores are checked too, including self-signed roots. Trivy does not validate certificate chains or determine whether a root is used as a trust anchor.

You can suppress selected findings using `CRYPTO-0006` and optional file paths in the `crypto` section of [`.trivyignore.yaml`](https://github.com/aquasecurity/trivy/blob/0bd8831e5d74eeea62ee9f11a95ba35f79b0cb49/docs/guide/configuration/filtering.md#trivyignoreyaml). Specify the file with `--ignorefile .trivyignore.yaml`; the certificates remain in the inventory.

An MD2, MD4, or MD5 fingerprint or a separate use of these hashes elsewhere in a file is not the certificate signature checked by this rule.

## References

- [RFC 6151: Updated Security Considerations for the MD5 Algorithm and the HMAC-MD5 Algorithm](https://www.rfc-editor.org/rfc/rfc6151)
- [RFC 6149: MD2 to Historic Status](https://www.rfc-editor.org/rfc/rfc6149)
- [RFC 6150: MD4 to Historic Status](https://www.rfc-editor.org/rfc/rfc6150)
- [CA/Browser Forum Baseline Requirements, Section 7.1.3.2](https://cabforum.org/working-groups/server/baseline-requirements/documents/)
