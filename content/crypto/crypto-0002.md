---
title: "CRYPTO-0002: Small RSA key"
id: CRYPTO-0002
aliases:
  - /crypto/CRYPTO-0002
source: Trivy
icon: aqua
severity: high
category: crypto
draft: false
summary: An RSA key is shorter than 2048 bits, below the baseline size for new RSA digital signatures in NIST transition guidance.
keywords: "CRYPTO-0002, RSA, key size, 2048"
breadcrumbs:
  - name: Cryptography
    path: /crypto
avd_page_type: avd_page
---

## What is checked

Trivy reports an RSA key with a known, positive key size of **less than 2048 bits**. For example, 1024-bit and 1536-bit RSA keys match this rule; 2048-bit and larger keys do not.

The finding belongs to the key asset, including when the public key was extracted from a certificate.

## Impact

Smaller RSA keys offer less resistance to factoring attacks, which can allow an attacker to recover the private key and undermine signatures or encrypted communications that depend on it. NIST SP 800-131A Rev. 2 uses 2048 bits as the minimum RSA modulus size for generating new digital signatures, corresponding to approximately 112 bits of classical security strength.

This is a fixed size check. Passing it does not establish that a key meets every protocol, compliance, or long-term protection requirement.

## Recommended actions

- Generate a replacement RSA key of at least 2048 bits, or use another supported algorithm that meets your security requirements. Choose a larger size if your policy or required protection period calls for it.
- Reissue certificates that contain the old public key and update applications to use the replacement key and certificate.
- Retire the old key after its remaining uses and dependencies have been addressed. For supplier-managed material, obtain an updated image, package, or certificate from the supplier.

## Scope and limitations

An RSA key of unknown size does not produce a finding. Trivy does not determine whether the key is used by an application, nor does this rule assess key generation quality, padding, or the strength of a certificate issuer's separate signing key.

## References

- [NIST SP 800-131A Rev. 2, Section 3: Digital Signatures](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf#page=14)
- [NIST SP 800-57 Part 1 Rev. 5: Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
