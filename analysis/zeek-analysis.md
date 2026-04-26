# Zeek Analysis — Operation SPECTRE

This document summarizes key observations derived from Zeek logs.

---

## Logs Used

* conn.log → connection patterns
* dns.log → domain resolution
* ssl.log → encrypted traffic

---

## 1. Beaconing Behavior

Repeated connections to external IPs were observed with relatively consistent time intervals (~20–30 seconds).

This pattern differs from normal user-driven traffic, which is typically irregular.

Interpretation:
Indicates potential automated communication (beaconing).

---

## 2. DNS → TLS Pattern

DNS queries were often followed by outbound TLS connections shortly after.

Interpretation:
Suggests staged communication (resolve → connect), commonly used by malware.

---

## 3. DNS Analysis

* Domains observed: beam.scs.splunk.com, reverse PTR lookups
* No long or encoded subdomains
* No excessive unique queries

Interpretation:
No evidence of DNS tunneling or data exfiltration.

---

## 4. TLS Observations

* Encrypted outbound traffic observed
* Limited metadata (expected in TLS)

Interpretation:
Encrypted channels reduce visibility, requiring behavioral detection.

---

## Conclusion

Zeek provided the primary visibility into behavioral patterns that were not detectable through signature-based detection alone.

Most key findings — especially beaconing — were identified through Zeek log analysis rather than IDS alerts.
