# ARPGuard 🛡️

Passive ARP cache monitor for Linux — detects suspicious ARP changes that may indicate ARP spoofing, without requiring `sudo`.

---

## ✨ Features
- **[Passive monitoring](ca://s?q=Passive_ARP_monitoring_Linux)** → polls `/proc/net/arp` instead of sniffing raw packets.
- **[Spoof detection](ca://s?q=Detect_ARP_spoofing_Linux)** → alerts when IP → MAC mappings change unexpectedly.
- **[Churn alerts](ca://s?q=ARP_churn_detection)** → flags rapid changes for the same IP.
- **[Multiple IPs per MAC](ca://s?q=MAC_multiple_IPs_detection)** → detects suspicious devices claiming many IPs.
- **[Duplicate IPs](ca://s?q=Duplicate_IP_detection)** → warns if an IP is seen with multiple MACs.
- **[Cross‑distro friendly](ca://s?q=Linux_cross_distro_ARP_monitor)** → works on Fedora, Ubuntu, Arch, Debian — any Linux with `/proc/net/arp`.

---

## 🚀 Installation
Clone the repo and run with Python 3:

```bash
git clone https://github.com/neo4-svg/arpmonitor.git
cd arpguard
python3 arpguard.py --interval 5 --log arpguard.jsonl
```
