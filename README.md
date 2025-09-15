# 🛰️ Bypassing Proxy Connection Issues with a Custom Upstream Proxy

This project provides a **lightweight Python-based upstream proxy** to help penetration testers route traffic through **Burp Suite** (or any local proxy) even when an application or browser **fails to connect directly through Burp**.  

Instead of relying on heavy tools, this script acts as an **intermediary forwarder**, passing all HTTP/HTTPS requests to your local Burp proxy allowing smooth interception without connection errors.

Requires python 3.8+, Works on both windows and linux


For technical details visit : https://the-it-wonders.blogspot.com/2025/09/bypassing-burpsuite-failed-to-connect.html

---

## ⚡ How It Works

**Internet <--> Python Upstream Proxy <--> Burp Suite <--> Browser / Mobile App**

- It listens locally on a port you define (e.g., default 127.0.0.1:8081).
- It accepts connections from your BurpSuite proxy.
- For normal HTTP requests, it forwards them to the target using modern libraries that support HTTP/2 and TLS 1.3.
- For HTTPS (CONNECT requests), it sets up a raw tunnel, allowing your interception proxy to handle SSL/TLS interception as usual.

---

## 📦 Requirements

- Python 3.8+ installed.
- `pip install httpx`
- Burp Suite running locally (default port 8080)

---

## ⚙️ Usage

```bash
usage: Python Bypass_proxy.py -p 8081 -v

Help:Python Bypass_proxy.py -h
bypass__proxy.py [-h] [-p PORT] [-b BIND] [-v] [--allow ALLOW]

Upstream proxy that handles modern TLS/HTTP2 to origin

options:
  -h, --help       show this help message and exit
  -p, --port PORT  Port to listen on (default: 8081)
  -b, --bind BIND  Bind address (default: 127.0.0.1)
  -v, --verbose    Verbose logging
  --allow ALLOW    Allowlist host[:port] (can repeat). If empty, all hosts allowed.
```
---

## ⚡ BurpSuite configuration

- Make sure burpsuite is running on any port.
- Make sure this proxy script is also running
- Go to **BurpSuite proxy settings** --> **Network** --> **Upstream proxy server** --> add the proxy details of this script.

  For-example: **destination host**= *, **proxy host**=127.0.0.1, **proxy port**=8081 --> **OK** --> Make sure the checkbox is on/checked


