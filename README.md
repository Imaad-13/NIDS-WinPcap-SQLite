# Network Intrusion Detection System (NIDS) - Windows

This is a real-time **Network Intrusion Detection System (NIDS)** implemented in **C++** using **WinPcap** for packet capture and **SQLite** for signature-based attack detection. It monitors a specified target IP and raises alerts based on pre-defined rules and traffic patterns like SYN floods, UDP floods, and known malicious signature matches.

---

## 📁 Project Structure

```
/NIDS
├── main/
│   ├── NIDS.cpp          # Main detection engine
│   ├── NIDS.exe          # Compiled executable (optional)
├── auxiliary/
│   └── Attacker.cpp      # Traffic simulator for testing (Linux-based)
├── database/
│   └── nids.db           # SQLite DB containing attack signatures
├── example-logs/
│   └── false_positives_test.log  # Captured test run output
```

---

## 🎯 Features

- Real-time network traffic monitoring using WinPcap
- SQLite-based signature matching
- SYN flood and UDP flood detection with rate-limiting
- Excludes multicast/SSDP traffic to reduce noise
- Coded alert throttling to avoid spamming
- Built-in test tool to simulate multiple types of attacks

---

## ⚙️ How It Works

1. User selects a network interface and target IP to monitor.
2. Signatures are loaded from `nids.db` SQLite database.
3. Each packet is parsed (TCP/UDP only), matched with rules, and checked for behavior anomalies (floods).
4. Alerts are printed on-screen with source, destination, and severity.

---

## 🧪 Auxiliary Attacker Tool

- Located at: `auxiliary/Attacker.cpp`
- Works only on **Linux** (uses `gnome-terminal` and `bash`)
- Simulates:
  - ICMP ping floods
  - HTTP request floods
  - Netcat connection loops
  - Broadcast pings
  - Large packet pings

---

## 🧾 Example Logs

**Location:** `/example-logs/`

Included is a sample log from an actual test run:
- SYN flood and UDP flood detections
- DNS-related alerts
- Demonstrates how false positives can occur from legitimate sources

---

## 🛠️ Future Work: Addressing False Positives

While the NIDS performs well in detecting known attacks, several false positives have been identified:

### Known Issues:
- ⚠️ High-volume TCP traffic (from cloud services) incorrectly flagged
- ⚠️ DNS responses from internal LAN hosts detected as malicious
- ⚠️ Repetitive alerts from legit UDP streams

### Planned Improvements:
- Configurable whitelisting (e.g., trusted IP ranges)
- Adjustable thresholds for flood detection
- Logging to file with timestamps for post-analysis
- Web-based dashboard or UI for live monitoring
- DPI (Deep Packet Inspection) support in future releases

---

## 📋 Database Schema

```sql
CREATE TABLE signatures (
    signature TEXT,
    protocol TEXT,
    src_ip TEXT,
    dest_ip TEXT,
    src_port INTEGER,
    dest_port INTEGER,
    action TEXT,
    description TEXT,
    severity INTEGER
);
```

- Use `"Any"` for wildcard matches
- Severity: `1` (low) to `5` (critical)

---

## 💻 Installation & Usage

### Requirements:
- Windows OS
- WinPcap (or npcap in compatibility mode)
- SQLite3
- C++17

### Compile (using g++ on Windows):
```bash
g++ -std=c++17 NIDS.cpp -o NIDS.exe -lwpcap -lws2_32 -lsqlite3
```

### Run:
1. Launch `NIDS.exe`
2. Select interface number
3. Enter the target IP to monitor
4. Watch alerts stream live

---

## 👨‍💻 Author

**Imaad Ikramul Fasih**  
Cybersecurity Developer  
🔗 https://github.com/Imaad-13  
🔗 https://linkedin.com/in/imaadikramulfasih

---

## 📄 License

This project is licensed under the [MIT License](LICENSE.txt).
