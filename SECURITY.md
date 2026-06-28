# Security Policy

## Reporting a vulnerability

Use GitHub Security Advisories / private reporting. Do not open a public issue for security bugs.

Include:
1. `cape --version` output.
2. The upstream the vulnerability was observed against (do **not** include
   credentials).
3. A minimal reproduction — ideally with `mockevil` or any local
   stub provider that returns the malicious chunk you used.
4. The alert line from `carapace.log` if `cape` caught it, or the exact response
   that bypassed detection.

## Trust boundaries

`carapace` runs as a local process with read access to your upstream API key.
It:

- forwards requests **verbatim**;
- never writes the upstream key anywhere (memory is `zeroize`d on drop);
- never writes request/response bodies to disk (only alert metadata + a 512-byte
  snippet of the suspicious buffer);
- runs as a single static binary with **no** network egress except to the
  `--upstream` you configured.

If any of these properties break under audit, treat it as a critical
vulnerability.
