# Legal Disclaimer

Cuttix is a network administration and security auditing tool. It includes
functionality that can disrupt network communications (ARP spoofing) and
intercept network traffic (packet capture).

## Authorized Use Only

This tool is intended for use **only** on networks you own or have explicit
written authorization to test. Unauthorized use is illegal in most jurisdictions.

### Applicable French Law (Code Pénal)

- **Art. 323-1**: Unauthorized access to a computer system — up to 3 years imprisonment, €100,000 fine
- **Art. 323-2**: Obstructing the operation of a computer system — up to 5 years, €150,000 fine
- **Art. 323-3**: Fraudulent introduction or modification of data — up to 5 years, €150,000 fine

### Legal Use Cases

- Networks you personally own and administer
- Corporate networks with written authorization from the owner
- Isolated test labs (VMs, GNS3, Docker)
- Penetration tests covered by a signed engagement letter

## Audit Trail

All ARP spoofing actions are logged in a tamper-evident, HMAC-signed audit log.
This logging cannot be disabled. The log records: operator IP, target IP/MAC,
action type, and timestamp.

## No Warranty

This software is provided "as is" without warranty of any kind. The authors are
not liable for any damages arising from the use of this software.

See the [LICENSE](LICENSE) file for the full GPLv3 license text.
