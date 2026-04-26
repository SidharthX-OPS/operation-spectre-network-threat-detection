# Lab Setup — Operation SPECTRE

This lab was built to understand how network traffic looks from a detection perspective — not just running tools, but actually seeing how different types of activity show up in logs.

---

## Environment

I set this up on an Ubuntu 22.04 VM and used three main tools:

* **Suricata** for alert-based detection
* **Zeek** for detailed network logs
* **Splunk** to search and correlate everything

All three were running on the same system so I could compare outputs directly.

---

## How Traffic Was Monitored

Both Suricata and Zeek were configured to monitor the same network interface.

That was important because I didn’t want two different views of traffic — I wanted to see how:

* Suricata reacts (alerts)
* Zeek records behavior (logs)

for the exact same packets.

---

## Log Flow into Splunk

* Suricata logs (`eve.json`) were sent to a `suricata` index
* Zeek logs (`conn.log`, `dns.log`, `ssl.log`) were sent to a `zeek` index

This made it possible to connect:

> “Suricata fired an alert here”
> with
> “What was actually happening in the traffic?”

---

## Generating Traffic

I didn’t use live malware for this project.

Instead, I:

* captured traffic using `tcpdump`
* replayed it using `tcpreplay`

This kept everything controlled and repeatable, which made analysis much easier.

---

## Detection Setup

* Enabled Suricata’s Emerging Threats rules
* Added my own custom rule for detecting repeated HTTP connections (beaconing pattern)
* Used Zeek mainly for behavioral analysis rather than detection rules

---

## Splunk Usage

Splunk was where everything came together.

I used it to:

* identify repeated connections
* analyze DNS query patterns
* correlate Suricata alerts with Zeek logs

Most of the actual “understanding” of what was happening came from here.

---

## Final Note

This lab is based on simulated traffic.

The focus wasn’t on running malware, but on learning how to recognize patterns that *look like* malicious behavior — things like beaconing, staged communication, and abnormal traffic patterns.

That turned out to be way more useful than just triggering alerts.
