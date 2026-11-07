# Verification Instructions for GOCUP 1

**Contest Identifier:** `gocup-1`
**Contest UUID:** `3beefbc0-c191-413b-87d5-71725a08aeaa`
**Organizer:** Sharif University Computer Society

---

## Cryptographic Key Fingerprints

- **Manifest Signing Public Key:** `b9a005965a9a0d7c9f9b13d9a7ee777fbd18be3819748af2efcf8076793daf22`
  - Fingerprint: `SHA256:c92f13d7e331759e5e0983ad3d43986452e6b3b56f70f1530c0ce59bc6d9a47e`
- **Judge Decryption Public Key:** `64653cc820264a34a23392747484db156094969685c463a5736c854d329f8d70`
  - Fingerprint: `SHA256:ef9668a20aa1bfb91938c17f08caea4a3ce79e9032da1513670b417e5480bb50`

---

## Verifying Manifest Authenticity

Run the verification tool with the organizer's public key:

```bash
warm_judge_app verify-manifest \
  --manifest ./manifests/contest_manifest.json \
  --signature ./manifests/contest_manifest.json.sig \
  --public-key ./configuration/manifest_signing_key.pub
```
