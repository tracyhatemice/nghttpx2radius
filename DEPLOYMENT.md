# nghttpx2radius Daemon Deployment Guide

## Overview

nghttpx2radius v5.0.0 is a daemon that continuously monitors nghttpx access logs from journald and sends RADIUS accounting information in real-time. It maintains active sessions for each user+IP combination and sends periodic interim updates.

## Features

- **Real-time monitoring**: Continuously follows journald logs for immediate session creation
- **Session management**: Tracks active sessions per user+IP combination
- **Interim updates**: Sends periodic accounting updates (configurable, default 15 minutes)
- **Session timeout**: Automatically closes sessions when no activity is detected
- **Graceful shutdown**: Properly closes all active sessions on daemon shutdown
- **Syslog integration**: Logs all activity to syslog/journald for monitoring

## Prerequisites

- Linux system with systemd and journald
- nghttpx service running and logging to journald
- Go 1.24 or later (for building from source)
- RADIUS accounting server with shared secret
- User with access to journald logs (typically in `systemd-journal` group)

## Installation

### 1. Build the Binary

```bash
# Clone the repository
git clone https://github.com/tracyhatemice/nghttpx2radius.git
cd nghttpx2radius

# Build the binary
go build -o nghttpx2radius

# Install the binary
sudo cp nghttpx2radius /usr/local/bin/
sudo chmod +x /usr/local/bin/nghttpx2radius
```

### 2. Create Service User (Optional but Recommended)

For better security, create a dedicated user for the service:

```bash
# Create system user
sudo useradd -r -s /usr/sbin/nologin -d /nonexistent nghttpx2radius

# Add user to systemd-journal group for log access
sudo usermod -a -G systemd-journal nghttpx2radius
```

### 3. Configure the Service

Edit the systemd service file to match your environment:

```bash
sudo cp nghttpx2radius.service /etc/systemd/system/
sudo nano /etc/systemd/system/nghttpx2radius.service
```

Update the following parameters in the `ExecStart` line:

- `YOUR_RADIUS_SERVER`: Your RADIUS server hostname or IP
- `YOUR_RADIUS_SECRET`: Your RADIUS shared secret
- `-radius-acct-port`: RADIUS accounting port (default: 1813)
- `-radius-nasid`: NAS identifier sent to RADIUS (default: nghttpx)
- `-nghttpx-service`: systemd service name for nghttpx (default: nghttpx)
- `-interim-interval`: Interim update interval in minutes (default: 15)

**Optional parameters:**

- `-exclude-pattern`: Regex pattern to exclude usernames from accounting
- `-dry-run`: Run without sending to RADIUS server (for testing)

If you created a dedicated user, also update:

```ini
User=nghttpx2radius
Group=nghttpx2radius
```

### 4. Enable and Start the Service

```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable nghttpx2radius

# Start the service
sudo systemctl start nghttpx2radius
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `-radius-server` | (required) | RADIUS server hostname or IP address |
| `-radius-secret` | (required) | RADIUS shared secret |
| `-radius-acct-port` | 1813 | RADIUS accounting port |
| `-radius-nasid` | nghttpx | RADIUS NAS Identifier |
| `-nghttpx-service` | nghttpx | systemd service name for nghttpx |
| `-interim-interval` | 15 | Interim update interval in minutes (minimum: 1) |
| `-exclude-pattern` | (none) | Regex pattern to exclude usernames |
| `-dry-run` | false | Run without sending to RADIUS server |

## Operation

### Session Lifecycle

1. **Session Start**: When a new user+IP combination is detected in the logs:
   - Create session with unique session ID
   - Send `Accounting-Start` to RADIUS server
   - Store session in memory

2. **Session Active**: While logs continue to arrive for the session:
   - Update byte counters
   - Send `Interim-Update` every N minutes (configurable)
   - Reset activity timer

3. **Session Timeout**: When no logs arrive for the interim interval:
   - Send `Accounting-Stop` to RADIUS server
   - Remove session from memory
   - Final session time = last activity - first activity

4. **Graceful Shutdown**: When daemon receives SIGTERM/SIGINT:
   - Stop monitoring logs
   - Send `Accounting-Stop` for all active sessions
   - Log shutdown completion

### RADIUS Accounting Packets

**Accounting-Start** (sent when session begins):
- User-Name
- Acct-Session-ID (Unix timestamp)
- Acct-Status-Type = Start
- NAS-Identifier
- Calling-Station-ID (client IP)
- Called-Station-ID (local IP)

**Interim-Update** (sent periodically):
- All Start attributes, plus:
- Acct-Output-Octets (total bytes)
- Acct-Session-Time (elapsed seconds)

**Accounting-Stop** (sent when session ends):
- All Interim attributes, plus:
- Acct-Terminate-Cause = User-Request

## Monitoring

### Check Service Status

```bash
# View service status
sudo systemctl status nghttpx2radius

# View recent logs
sudo journalctl -u nghttpx2radius -f

# View logs since boot
sudo journalctl -u nghttpx2radius -b
```

### Log Messages

The daemon logs to syslog/journald with the identifier `nghttpx2radius`. Key log messages:

- `nghttpx2radius daemon v5.0.0 starting`: Daemon startup
- `Daemon started successfully`: All components initialized
- `New session: <user> from <ip>`: Session created
- `Sent Accounting-Start for <user> from <ip>`: Start packet sent
- `Interim update: <user> from <ip>`: Periodic update triggered
- `Session timeout: <user> from <ip>`: Session closed due to inactivity
- `Received signal <sig>, shutting down gracefully`: Shutdown initiated
- `Closing all active sessions`: Cleanup started
- `Daemon stopped`: Shutdown complete

### Error Messages

- `Failed to send Accounting-Start`: Network or RADIUS server issue
- `Failed to send Interim-Update`: Network or RADIUS server issue
- `Failed to send Accounting-Stop`: Network or RADIUS server issue
- `Error starting journalctl`: Cannot read logs (check permissions)
- `Failed to get called station IP`: Network configuration issue

## Troubleshooting

### Service Won't Start

1. Check configuration:
   ```bash
   sudo journalctl -u nghttpx2radius -n 50
   ```

2. Verify RADIUS server connectivity:
   ```bash
   nc -zv <radius-server> 1813
   ```

3. Check user permissions:
   ```bash
   groups nghttpx2radius
   # Should include: systemd-journal
   ```

### No Sessions Being Created

1. Verify nghttpx is logging:
   ```bash
   sudo journalctl -u nghttpx -n 20
   ```

2. Check nghttpx log format matches expected pattern:
   - Should include: `[CN:"<subject>"]` with certificate subject
   - Example: `::ffff:192.168.1.100 - [CN:"UID=user1,CN=user1"] [12/Nov/2025:14:12:16 +0000] "CONNECT example.com:443 HTTP/2" 200 9436 "-" "Mozilla/..."`

3. Test in dry-run mode:
   ```bash
   sudo /usr/local/bin/nghttpx2radius \
     -radius-server=test.example.com \
     -radius-secret=test \
     -dry-run
   ```

### Sessions Not Closing

1. Check interim interval setting (must be reasonable):
   ```bash
   systemctl cat nghttpx2radius | grep interim-interval
   ```

2. Verify session checker is running:
   ```bash
   sudo journalctl -u nghttpx2radius | grep "Session checker"
   ```

### RADIUS Server Not Receiving Packets

1. Check firewall rules:
   ```bash
   sudo iptables -L -n | grep 1813
   ```

2. Verify RADIUS server is listening:
   ```bash
   sudo tcpdump -i any port 1813
   ```

3. Test RADIUS connectivity:
   ```bash
   echo "User-Name=test" | radclient <server>:1813 acct <secret>
   ```

## Maintenance

### Restart Service

```bash
# Graceful restart (closes all sessions first)
sudo systemctl restart nghttpx2radius
```

### Update Configuration

```bash
# Edit service file
sudo nano /etc/systemd/system/nghttpx2radius.service

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart nghttpx2radius
```

### Upgrade

```bash
# Build new version
cd nghttpx2radius
git pull
go build -o nghttpx2radius

# Stop service
sudo systemctl stop nghttpx2radius

# Replace binary
sudo cp nghttpx2radius /usr/local/bin/

# Start service
sudo systemctl start nghttpx2radius
```

## Security Considerations

1. **Protect RADIUS secret**: Store in service file with restricted permissions
   ```bash
   sudo chmod 600 /etc/systemd/system/nghttpx2radius.service
   ```

2. **Run as dedicated user**: Don't run as root
   ```bash
   # Service file should have:
   User=nghttpx2radius
   Group=nghttpx2radius
   ```

3. **Limit file system access**: Use systemd security features
   ```bash
   # Service file includes:
   ProtectSystem=strict
   ProtectHome=true
   PrivateTmp=true
   NoNewPrivileges=true
   ```

4. **Monitor logs**: Set up alerts for errors
   ```bash
   sudo journalctl -u nghttpx2radius -p err -f
   ```

5. **Network security**: Restrict RADIUS traffic with firewall
   ```bash
   sudo iptables -A OUTPUT -p udp --dport 1813 -d <radius-server> -j ACCEPT
   sudo iptables -A OUTPUT -p udp --dport 1813 -j DROP
   ```

## Performance Tuning

### High Traffic Environments

For high-traffic nghttpx servers (>1000 req/s):

1. **Increase file descriptor limit**:
   ```ini
   # In service file:
   LimitNOFILE=131072
   ```

2. **Adjust interim interval**:
   ```ini
   # Longer intervals reduce RADIUS traffic:
   -interim-interval=30
   ```

3. **Monitor resource usage**:
   ```bash
   systemctl status nghttpx2radius
   # Check Memory and CPU usage
   ```

### Memory Usage

The daemon stores active sessions in memory. Estimate memory usage:

```
Memory per session ≈ 200 bytes
1000 concurrent users ≈ 200 KB
10000 concurrent users ≈ 2 MB
```

## Backup and Recovery

### Session Data

**Important**: Session data is stored in memory only and is lost on restart. This is by design for simplicity and performance.

On restart:
1. All old sessions are closed (Accounting-Stop sent)
2. New sessions are created as users generate new traffic
3. Brief accounting gap during restart (typically <1 minute)

### Configuration Backup

```bash
# Backup service configuration
sudo cp /etc/systemd/system/nghttpx2radius.service \
   /etc/systemd/system/nghttpx2radius.service.bak

# Backup binary
sudo cp /usr/local/bin/nghttpx2radius \
   /usr/local/bin/nghttpx2radius.bak
```

## Migration from v4.x

The daemon version (v5.x) is a significant architectural change from the cron-based v4.x:

### Key Differences

| Feature | v4.x | v5.x |
|---------|------|------|
| Execution | Periodic (cron) | Continuous (daemon) |
| Session tracking | Batch processing | Real-time per session |
| Accounting | Start+Stop per batch | Start+Interim+Stop per session |
| Session time | Fixed/estimated | Accurate (first-last) |
| Restart impact | None | Sessions closed |

### Migration Steps

1. **Stop cron job**:
   ```bash
   crontab -e
   # Comment out or remove nghttpx2radius line
   ```

2. **Install v5.x** (follow Installation section above)

3. **Test in dry-run mode first**:
   ```bash
   sudo systemctl stop nghttpx2radius
   sudo /usr/local/bin/nghttpx2radius -radius-server=test -radius-secret=test -dry-run
   # Monitor logs to verify session detection
   # Press Ctrl+C to stop
   ```

4. **Enable production mode**:
   ```bash
   # Remove -dry-run from service file
   sudo nano /etc/systemd/system/nghttpx2radius.service
   sudo systemctl daemon-reload
   sudo systemctl start nghttpx2radius
   ```

5. **Monitor RADIUS server** to verify accounting records

### Rollback Plan

If you need to rollback:

```bash
# Stop v5.x daemon
sudo systemctl stop nghttpx2radius
sudo systemctl disable nghttpx2radius

# Reinstall v4.x binary
sudo cp /usr/local/bin/nghttpx2radius.v4.bak /usr/local/bin/nghttpx2radius

# Restore cron job
crontab -e
# Add back the periodic execution line
```

## Support

- GitHub Issues: https://github.com/tracyhatemice/nghttpx2radius/issues
- Documentation: https://github.com/tracyhatemice/nghttpx2radius

## License

See LICENSE file in the repository.
