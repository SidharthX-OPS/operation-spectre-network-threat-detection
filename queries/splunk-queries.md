# Splunk Detection Queries — Operation SPECTRE

This file contains the main SPL queries used during analysis.

---

## 1. Beacon Detection (Low Variance Connections)

Detects hosts making repeated connections with consistent timing — a strong indicator of beaconing.

```spl
index=zeek sourcetype=zeek_conn
| bin _time span=1m
| stats count as conn_count by _time, id.orig_h, id.resp_h
| stats avg(conn_count) as avg, stdev(conn_count) as stdev by id.orig_h, id.resp_h
| eval beacon_score = round(avg / (stdev + 0.001), 2)
| where beacon_score > 5
| sort - beacon_score
```

---

## 2. Top External Connections

Shows which external IPs are contacted most frequently.

```spl
index=zeek sourcetype=zeek_conn
| stats count by id.orig_h, id.resp_h
| sort - count
```

---

## 3. DNS Query Frequency

Used to analyze domain resolution behavior.

```spl
index=zeek sourcetype=zeek_dns
| stats count by query
| sort - count
```

---

## 4. Cross-Layer Correlation (Suricata + Zeek)

Correlates Suricata alerts with Zeek connection data.

```spl
index=suricata event_type=alert
| rename src_ip as ip
| join type=left ip [
    search index=zeek sourcetype=zeek_conn
    | rename id.orig_h as ip
    | stats sum(orig_bytes) as bytes_sent by ip
]
| table _time, ip, alert.signature, bytes_sent
```
