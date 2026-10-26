---
title: "CRYPTO-0001: SHA-1 certificate signature"
id: CRYPTO-0001
aliases:
  - /crypto/CRYPTO-0001
source: Trivy
icon: aqua
severity: medium
category: crypto
draft: false
summary: An X.509 certificate is signed using SHA-1, whose collision resistance is no longer suitable for generating digital signatures.
keywords: "CRYPTO-0001, SHA-1, certificate, signature"
breadcrumbs:
  - name: Cryptography
    path: /crypto
avd_page_type: avd_page
---

## What is checked

Trivy reports an X.509 certificate whose signature algorithm identifies SHA-1 with RSA, DSA, or ECDSA. The finding concerns the signature on the certificate, which was created by its issuer. It does not describe the algorithm of the certificate's own public key.

## Impact

SHA-1 has weaknesses in its collision resistance, a property needed for digital signatures to reliably protect the signed content. NIST recommends transitioning away from SHA-1 and restricts its use for generating new digital signatures. A certificate's impact depends on how it is used and trusted; finding it in an image does not establish that an application uses it.

## Recommended actions

- Have the issuer reissue application certificates using a supported signature algorithm with SHA-256 or a stronger appropriate hash.
- Update the certificate authority configuration so newly issued certificates use the replacement algorithm.
- For certificates supplied by a base image, operating system package, or third party, review updates from that supplier. Review trust requirements before removing a certificate from a trust store.

## Scope and limitations

Certificates in system trust stores are checked too, including self-signed roots. Trivy does not validate certificate chains or determine whether a root is used as a trust anchor.

RSA-PSS certificate signatures are not covered by this check because Trivy does not inspect their hash parameters. A SHA-1 fingerprint or a separate use of SHA-1 elsewhere in a file is not the certificate signature checked by this rule.

## References

- [NIST policy on hash functions](https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions)
- [NIST SP 800-131A Rev. 2, Section 9: Hash Functions](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf#page=24)
