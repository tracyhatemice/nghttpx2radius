# nghttpx2radius

A daemon that continuously monitors nghttpx access logs from systemd journald and sends real-time RADIUS accounting information. It tracks active sessions per user+IP combination and sends periodic interim updates.

## Features

- **Real-time monitoring**: Continuously follows journald logs for immediate session tracking
- **Session management**: Maintains active sessions per user+IP combination
- **Accurate session timing**: Calculates actual session duration (first activity to last activity)
- **Interim updates**: Sends periodic accounting updates (configurable interval, default 15 minutes)
- **Automatic session cleanup**: Closes sessions after inactivity timeout
- **Graceful shutdown**: Properly closes all active sessions on daemon stop
- **Username extraction**: Supports both UID and CN fields from client certificates
- **IPv4-mapped IPv6 conversion**: Automatically converts addresses to pure IPv4 format
- **User exclusion**: Regex pattern support for excluding specific users
- **Syslog integration**: All logs sent to syslog/journald for monitoring
- **Dry-run mode**: Test mode without sending to RADIUS server

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

## Quick Start

### Installation

```bash
# Build and install
git clone https://github.com/tracyhatemice/nghttpx2radius.git
cd nghttpx2radius
go build -o nghttpx2radius
sudo cp nghttpx2radius /usr/local/bin/

# Install systemd service
sudo cp nghttpx2radius.service /etc/systemd/system/
sudo nano /etc/systemd/system/nghttpx2radius.service  # Edit configuration
sudo systemctl daemon-reload
sudo systemctl enable nghttpx2radius
sudo systemctl start nghttpx2radius
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed installation and configuration instructions.

## Usage

### As a Daemon (Recommended)

The daemon runs continuously and monitors logs in real-time:

```bash
nghttpx2radius \
  -radius-server 192.168.1.100 \
  -radius-secret your_shared_secret \
  -interim-interval 15
```

The daemon will:
1. Monitor journald logs continuously
2. Create accounting sessions for new user+IP combinations
3. Send interim updates every 15 minutes
4. Close sessions after 15 minutes of inactivity
5. Handle graceful shutdown on SIGTERM/SIGINT

### Dry Run (Test Mode)

Test without sending to RADIUS server:

```bash
nghttpx2radius \
  -radius-server 192.168.1.100 \
  -radius-secret my_secret \
  -dry-run
```

### Exclude Specific Users

Skip users matching a regex pattern:

```bash
nghttpx2radius \
  -radius-server 192.168.1.100 \
  -radius-secret my_secret \
  -exclude-pattern "test|anonymous"
```

## Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-radius-server` | *(required)* | RADIUS server address |
| `-radius-secret` | *(required)* | RADIUS shared secret |
| `-interim-interval` | `15` | Interim update interval in minutes (minimum: 1) |
| `-radius-acct-port` | `1813` | RADIUS accounting port |
| `-radius-nasid` | `nghttpx` | RADIUS NAS Identifier |
| `-nas-ip-address` | *(empty)* | NAS IP Address sent to RADIUS server (optional) |
| `-nghttpx-service` | `nghttpx` | Systemd service name for nghttpx |
| `-exclude-pattern` | *(empty)* | Regex pattern to exclude usernames |
| `-dry-run` | `false` | Run without sending to RADIUS server |
| `-version` | - | Print version and exit |

## Monitoring

### Check Daemon Status

```bash
# Service status
sudo systemctl status nghttpx2radius

# View logs
sudo journalctl -u nghttpx2radius -f

# View recent errors
sudo journalctl -u nghttpx2radius -p err -n 50
```

### Key Log Messages

- `New session: <user> from <ip>` - Session created
- `Sent Accounting-Start` - Start packet sent
- `Interim update: <user> from <ip>` - Periodic update
- `Session timeout: <user> from <ip>` - Session closed due to inactivity
- `Closing all active sessions` - Graceful shutdown in progress

## Certificate Subject Name Processing

The program extracts usernames from client certificate subject names:

- **Priority**: UID field (if present), otherwise CN field
- **Example 1**: `UID=john,CN=john` → username: `john`
- **Example 2**: `emailAddress=user@example.com,CN=user1,OU=Users,O=Company,C=US` → username: `user1`

## IPv4-Mapped IPv6 Address Conversion

Addresses in IPv4-mapped IPv6 format are automatically converted:

- `::ffff:192.168.1.100` → `192.168.1.100`

## How It Works

### Session Lifecycle

1. **Monitoring**: Daemon continuously follows journald logs using `journalctl -f`

2. **Session Creation**: When a new user+IP combination is detected:
   - Parse log line to extract username, IP, and bytes
   - Create in-memory session with unique session ID
   - Send RADIUS Accounting-Start packet
   - Initialize session timers (first seen, last seen, last update)

3. **Session Updates**: For each new log line from existing session:
   - Update last activity timestamp
   - Accumulate byte counters
   - Keep session alive

4. **Interim Updates**: Every N minutes (default 15):
   - Check all active sessions
   - If session has activity and hasn't been updated recently:
     - Calculate session time (now - first seen)
     - Send RADIUS Interim-Update with current bytes and time
     - Update last update timestamp

5. **Session Timeout**: If no activity for N minutes:
   - Calculate final session time (last seen - first seen)
   - Send RADIUS Accounting-Stop packet
   - Remove session from memory

6. **Graceful Shutdown**: On SIGTERM/SIGINT:
   - Stop log monitoring
   - Send Accounting-Stop for all active sessions
   - Exit cleanly

### RADIUS Packets

**Accounting-Start** (new session):
- User-Name, Acct-Session-ID, NAS-Identifier
- NAS-IP-Address (if `-nas-ip-address` flag is set)
- Calling-Station-ID (client IP), Called-Station-ID (local IP)
- Acct-Status-Type = Start

**Interim-Update** (periodic):
- All Start attributes plus:
- Acct-Output-Octets (total bytes transferred)
- Acct-Session-Time (seconds since session start)
- Acct-Status-Type = Interim-Update

**Accounting-Stop** (session end):
- All Interim attributes plus:
- Acct-Terminate-Cause = User-Request
- Acct-Status-Type = Stop

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

## Architecture Changes from v4.x

Version 5.0.0 is a major architectural change from the cron-based v4.x:

| Feature | v4.x (Batch) | v5.x (Daemon) |
|---------|--------------|---------------|
| Execution | Periodic (cron) | Continuous (daemon) |
| Session tracking | Batch aggregation | Real-time per session |
| Accounting packets | Start+Stop only | Start+Interim+Stop |
| Session time | Estimated | Accurate (first-last) |
| Memory usage | None (stateless) | Per-session state |
| Restart impact | None | Sessions closed |

See [DEPLOYMENT.md](DEPLOYMENT.md) for migration instructions.

## Version

Current version: 5.0.0
