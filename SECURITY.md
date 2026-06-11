# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report them privately via [GitHub's private vulnerability reporting](https://github.com/Jastchi/dotseal/security/advisories/new). This keeps the details confidential until a fix is released.

Include as much of the following as you can:

- A description of the vulnerability and its impact.
- Steps to reproduce or a proof-of-concept (even a partial one is helpful).
- The version of dotseal you tested against.
- Whether you believe a workaround exists.

You can expect an acknowledgement within **72 hours** and a status update within **7 days**.

## Scope

Issues of particular interest:

- Ciphertext reuse or nonce misuse in AES-GCM.
- AAD binding bypass (swapping ciphertext between variable names).
- Key material leaking to disk, logs, or process memory beyond what is documented.
- Timing side-channels in key comparison or fingerprint verification.
- `dotseal edit` temp-file exposure.

Out of scope:

- Vulnerabilities in underlying Python standard library crypto primitives.
- "The key was stolen" — dotseal is only as secure as the key store you use.
- Issues requiring physical access to the machine.

## Disclosure policy

We follow coordinated disclosure. Once a fix is available we will publish a GitHub Security Advisory and release a patched version. Credit is given to reporters who wish to be named.
