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
summary: An X.509 certificate is signed using MD2, MD4 or MD5, which must not be used for digital signatures.
keywords: "CRYPTO-0006, MD2, MD4, MD5, certificate, signature"
breadcrumbs:
  - name: Cryptography
    path: /crypto
avd_page_type: avd_page
---

## What is checked

Trivy reports an X.509 certificate whose signature algorithm identifies MD2, MD4 or MD5 with RSA. The finding concerns the signature on the certificate, which was created by its issuer. It does not describe the algorithm of the certificate's own public key.

## Impact

MD4 and MD5 have practical collision attacks. Known attacks on MD2 are not practical yet, but MD2 is not one-way, and RFC 6149 says it must not be used for digital signatures. RFC 6150 moved MD4 to Historic, and RFC 6151 says MD5 must not be used for digital signatures. The CA/Browser Forum Baseline Requirements do not allow these hashes in certificates. With a collision, an attacker can get the issuer to sign one certificate and reuse the signature on another certificate with different content. A certificate's impact depends on how it is used and trusted; finding it in an image does not establish that an application uses it.

## Recommended actions

- Have the issuer reissue application certificates using a supported signature algorithm with SHA-256 or a stronger appropriate hash.
- Update the certificate authority configuration so newly issued certificates use the replacement algorithm.
- For certificates supplied by a base image, operating system package, or third party, review updates from that supplier. Review trust requirements before removing a certificate from a trust store.

## Scope and limitations

Certificates in system trust stores are checked too, including self-signed roots. Trivy does not validate certificate chains or determine whether a root is used as a trust anchor.

You can suppress selected findings using `CRYPTO-0006` and optional file paths in the `crypto` section of [`.trivyignore.yaml`](https://github.com/aquasecurity/trivy/blob/0bd8831e5d74eeea62ee9f11a95ba35f79b0cb49/docs/guide/configuration/filtering.md#trivyignoreyaml). Specify the file with `--ignorefile .trivyignore.yaml`; the certificates remain in the inventory.

An MD2, MD4 or MD5 fingerprint or a separate use of these hashes elsewhere in a file is not the certificate signature checked by this rule.

## References

- [RFC 6151: Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms](https://www.rfc-editor.org/rfc/rfc6151)
- [RFC 6149: MD2 to Historic Status](https://www.rfc-editor.org/rfc/rfc6149)
- [RFC 6150: MD4 to Historic Status](https://www.rfc-editor.org/rfc/rfc6150)
- [CA/Browser Forum Baseline Requirements, Section 7.1.3.2](https://cabforum.org/working-groups/server/baseline-requirements/documents/)
