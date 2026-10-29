---
title: "CRYPTO-0005: Small EC private key"
id: CRYPTO-0005
aliases:
  - /crypto/CRYPTO-0005
source: Trivy
icon: aqua
severity: critical
category: crypto
draft: false
summary: The private key of a P-256, P-384 or P-521 elliptic curve key is a small number, so it can be guessed.
keywords: "CRYPTO-0005, elliptic curve, EC, private key, small key, P-256, P-384, P-521"
breadcrumbs:
  - name: Cryptography
    path: /crypto
avd_page_type: avd_page
---

## What is checked

Trivy reports a P-256, P-384 or P-521 key whose public point equals `k*G` for a private key `k` from **1 to 255**, where `G` is the base point of the curve. The rule applies to both public and private keys, because the public point is enough to see that the private key is small.

A private key of a healthy EC key is a random number close to the size of the curve order. A value below 256 can be found by trying every candidate. The upper limit of 255 comes from the eMudhra incident, where all eight affected intermediate CA keys used values up to 255.

## Impact

Anyone who has the public key can recover the private key in at most 255 attempts. The key then gives no protection. An attacker can sign data on behalf of the owner, and a certificate issued for such a key can be abused to impersonate its subject.

## Recommended actions

- Generate a new key pair with a trusted random number generator and replace the affected key.
- Reissue certificates for the affected public key and deploy them wherever the old certificates are used.
- Revoke the certificates that were issued for the affected key.
- Treat anything that was signed with the key as untrusted.

## Scope and limitations

The rule checks only keys on the P-256, P-384 and P-521 curves. Keys on other curves and keys of other algorithms do not produce a finding.

The rule only detects private keys from 1 to 255. A private key that is weak for another reason, for example a value from a small but larger range, is not reported.

You can suppress selected findings using `CRYPTO-0005` and optional file paths in the `crypto` section of [`.trivyignore.yaml`](https://github.com/aquasecurity/trivy/blob/0bd8831e5d74eeea62ee9f11a95ba35f79b0cb49/docs/guide/configuration/filtering.md#trivyignoreyaml). Specify the file with `--ignorefile .trivyignore.yaml`; the keys remain in the inventory.

See the [scanner documentation](https://github.com/aquasecurity/trivy/blob/0bd8831e5d74eeea62ee9f11a95ba35f79b0cb49/docs/guide/scanner/crypto.md) for supported key formats and parsing limitations.

## References

- [Mozilla Bugzilla: eMudhra intermediate CA keys with small private keys](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)
- [SEC 1: Elliptic Curve Cryptography, Section 3.2.1: Elliptic Curve Key Pair Generation Primitive](https://www.secg.org/sec1-v2.pdf)
