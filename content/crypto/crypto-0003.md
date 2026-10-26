---
title: "CRYPTO-0003: Weak elliptic curve"
id: CRYPTO-0003
aliases:
  - /crypto/CRYPTO-0003
source: Trivy
icon: aqua
severity: high
category: crypto
draft: false
summary: An elliptic curve has an estimated classical security level below 112 bits.
keywords: "CRYPTO-0003, elliptic curve, EC, classical security, 112"
breadcrumbs:
  - name: Cryptography
    path: /crypto
avd_page_type: avd_page
---

## What is checked

Trivy reports an EC algorithm asset whose estimated classical security level is **less than 112 bits**. An estimate of exactly 112 bits does not match this rule.

Classical security strength describes estimated resistance to attacks using classical computers. It is different from the curve's key size: for example, Trivy assigns P-256 a classical security level of 128 bits.

## Impact

Curves with lower security strength offer less resistance to attacks against the underlying discrete logarithm problem. Depending on their use, this can undermine digital signatures or key agreement. The 112-bit threshold follows the baseline strength in NIST SP 800-131A Rev. 2 for generating elliptic curve signatures and for approved elliptic curve key agreement.

## Recommended actions

- Replace affected keys with keys on a supported curve that meets your security requirements, such as P-256 or a stronger appropriate curve.
- Reissue affected certificates and update the applications or key agreement configuration that use the old keys.
- Review interoperability and protection-period requirements when choosing a replacement. A classical strength estimate does not establish resistance to quantum attacks.

## Scope and limitations

The rule can only evaluate curves that Trivy can parse and for which it can estimate a classical security level. A missing estimate does not produce a finding. See the [scanner documentation](https://github.com/aquasecurity/trivy/blob/3a0164d6cd627645220730d48d51dc71e10e7156/docs/guide/scanner/crypto.md) for supported algorithms and parsing limitations.

The finding refers to the EC algorithm asset rather than each individual key. Several keys using the same curve in one file may therefore share one finding. This rule does not assess the complete strength of a certificate signature or determine whether an application uses the algorithm.

## References

- [NIST SP 800-131A Rev. 2, Section 3: Digital Signatures](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf#page=14)
- [NIST SP 800-131A Rev. 2, Section 5: Key Agreement Using Diffie-Hellman and MQV](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf#page=18)
- [NIST SP 800-57 Part 1 Rev. 5, Section 5.6: Security Strength](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
