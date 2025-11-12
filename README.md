# nghttpx2radius

A tool to parse nghttpx access logs from systemd journald and send accounting information to a RADIUS server. This program aggregates traffic per user (extracted from client certificate subject names) and sends RADIUS accounting packets.

## Features

- Reads nghttpx access logs from systemd journald (no log files required)
- Extracts usernames from client certificate subject names (supports UID and CN fields)
- Converts IPv4-mapped IPv6 addresses to pure IPv4 format
- Aggregates traffic per user per IP address
- Sends RADIUS Accounting-Start and Accounting-Stop packets
- Configurable time range for log analysis
- Support for user exclusion patterns (regex)
- Dry-run mode for testing

## Requirements

- Linux system with systemd/journald
- nghttpx configured with custom access log format (see below)
- Access to journalctl (user must be in `systemd-journal` group or run with appropriate privileges)
- RADIUS accounting server

## nghttpx Configuration

Configure nghttpx with the following custom access log format:

```
accesslog-format=$remote_addr - [CN:"$tls_client_subject_name"] [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
accesslog-syslog=yes
```

Example log output:
```
Nov 12 14:13:17 localhost nghttpx[5453]: ::ffff:123.123.123.123 - [CN:"UID=user1,CN=user1"] [12/Nov/2025:14:12:16 +0000] "CONNECT signaler-pa.clients6.google.com:443 HTTP/2" 200 9436 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
```

## Installation

### Download Pre-built Binary

Download the latest release:

```bash
wget https://github.com/tracyhatemice/nghttpx2radius/releases/download/latest/nghttpx2radius-linux-amd64.tar.gz
tar -xzf nghttpx2radius-linux-amd64.tar.gz
sudo mv nghttpx2radius /usr/local/bin/
sudo chmod +x /usr/local/bin/nghttpx2radius
```

### Build from Source

```bash
git clone https://github.com/tracyhatemice/nghttpx2radius.git
cd nghttpx2radius
go build -o nghttpx2radius
```

## Usage

### Basic Usage

```bash
nghttpx2radius --radius-server 192.168.1.100 --radius-secret your_shared_secret
```

### Common Options

```bash
nghttpx2radius \
  --radius-server 192.168.1.100 \
  --radius-secret my_secret \
  --seek-time 60 \
  --radius-nasid nghttpx \
  --nghttpx-service nghttpx
```

### Dry Run (Test Mode)

Test without sending to RADIUS server:

```bash
nghttpx2radius \
  --radius-server 192.168.1.100 \
  --radius-secret my_secret \
  --dry-run
```

### Exclude Specific Users

Skip users matching a regex pattern:

```bash
nghttpx2radius \
  --radius-server 192.168.1.100 \
  --radius-secret my_secret \
  --exclude-pattern "test|user1mous"
```

## Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--radius-server` | *(required)* | RADIUS server address |
| `--radius-secret` | *(required)* | RADIUS shared secret |
| `--seek-time` | `60` | Time to look back in logs, in minutes |
| `--radius-acct-port` | `1813` | RADIUS accounting port |
| `--radius-nasid` | `nghttpx` | RADIUS NAS Identifier |
| `--nghttpx-service` | `nghttpx` | Systemd service name for nghttpx |
| `--exclude-pattern` | *(empty)* | Regex pattern to exclude usernames |
| `--dry-run` | `false` | Run locally without contacting RADIUS server |
| `--version` | - | Print version and exit |

## Running as Cron Job

Add to crontab to run hourly:

```bash
# Run every hour at minute 5
5 * * * * /usr/local/bin/nghttpx2radius --radius-server 192.168.1.100 --radius-secret your_secret >> /var/log/nghttpx2radius.log 2>&1
```

## Certificate Subject Name Processing

The program extracts usernames from client certificate subject names:

- **Priority**: UID field (if present), otherwise CN field
- **Example 1**: `UID=john,CN=john` → username: `john`
- **Example 2**: `emailAddress=user@example.com,CN=user1,OU=Users,O=Company,C=US` → username: `user1`

## IPv4-Mapped IPv6 Address Conversion

Addresses in IPv4-mapped IPv6 format are automatically converted:

- `::ffff:192.168.1.100` → `192.168.1.100`

## How It Works

1. Queries systemd journald for nghttpx logs from the last N minutes (default: 60)
2. Parses each log entry to extract:
   - Client IP address
   - Username from certificate subject
   - HTTP status code
   - Bytes transferred
3. Aggregates traffic per user per IP address
4. Sends RADIUS Accounting-Start and Accounting-Stop packets for each user/IP combination

## Building Releases

This project uses GitHub Actions to automatically build and release binaries. On every push to the `main` branch:

1. Builds a Linux amd64 binary with optimizations
2. Compresses to `.tar.gz`
3. Updates the `latest` release on GitHub

Manual trigger: Go to Actions → Build and Release → Run workflow

## Troubleshooting

### Permission Denied for journalctl

Add your user to the systemd-journal group:

```bash
sudo usermod -a -G systemd-journal $USER
```

Then log out and log back in.

### No Logs Found

Check that:
1. nghttpx is running and logging to journald
2. The service name matches (use `--nghttpx-service` flag)
3. The time range includes log entries (adjust `--seek-time`)

Verify logs manually:
```bash
journalctl -u nghttpx --since "1 hour ago" | grep CN:
```

## License

This project is a derivative of [squid2radius](https://github.com/tracyhatemice/squid2radius), modified to support nghttpx with journald.

## Version

Current version: 4.0.0
