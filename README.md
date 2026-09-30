# DNS Load Balancer

A custom DNS Server and Load Balancer designed to route traffic through healthy CDN IPs (Cloudflare, ArvanCloud, Fastly, Gcore). Ideal for V2Ray/Xray setups.

## How It Works
The service continuously checks a list of IPs (or CIDR ranges like `109.176.239.0/24`). It performs a TLS handshake with the CDN and runs an actual upload test (e.g., 500KB payload). The DNS server then returns the IP that has the fastest upload throughput and successful handshake.

## Cloudflare / DNS Setup
To use this tool, you must delegate a subdomain to your Ubuntu server:
1. **Create Subdomain 1 (The Server):** Create an `A` record (e.g., `ns1.example.com`) pointing to the public IP of your Ubuntu server. Make sure proxy is **OFF** (DNS Only).
2. **Create Subdomain 2 (The Load Balancer):** Create an `NS` record (e.g., `dl.example.com`) and point it to `ns1.example.com`.

Now, when users connect to `dl.example.com`, this app intercepts the DNS query and returns the absolute best working IP from your pool.

## Features
- **Real Payload Testing:** Tests actual upload bandwidth, not just simple pings. Drops IPs that handshake but fail to route real traffic.
- **Auto CIDR Scanning:** Add `109.176.239.0/24` to your list and it scans the entire range automatically.
- **Live Reload:** Edit your `.txt` IP lists on the fly. The service detects changes and updates its pools instantly without restarting.
- **Systemd Ready:** Built-in `--install` flag to automatically free port 53 and run as a background service on Linux.

## Installation (Ubuntu)

Compile the project:
```bash
dotnet clean
dotnet publish -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true
```

Install as a service:
```bash
sudo ./DnsLoadBalancer --install
```

View live logs:
```bash
sudo journalctl -u dnsloadbalancer.service -f
```

## Configuration (`appsettings.json`)
Edit `appsettings.json` to configure your domains, timeouts, and IP lists.
- `TlsCheckDomain`: The SNI used for the TLS handshake (e.g., your clean domain or CDN edge).
- `UploadTestSizeKB`: Data size for the throughput test (default: 500).
- `MaxHealthyIpsTarget`: Stops scanning once it finds enough healthy IPs to save CPU.
