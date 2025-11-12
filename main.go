package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

const version = "4.0.0"

type Config struct {
	RadiusServer     string
	RadiusSecret     string
	SeekTime         int
	RadiusAcctPort   string
	RadiusNASID      string
	NghttpxService   string
	ExcludePattern   string
	DryRun           bool
	excludeRegex     *regexp.Regexp
}

type UserStats struct {
	BytesByIP    map[string]int64
	SessionByIP  map[string]int64
}

func main() {
	config := parseArgs()

	if config.ExcludePattern != "" {
		var err error
		config.excludeRegex, err = regexp.Compile(config.ExcludePattern)
		if err != nil {
			log.Fatalf("Invalid exclude pattern: %v", err)
		}
	}

	fmt.Print("Analyzing.")
	userStats := analyzeLog(config)
	fmt.Println()

	if config.DryRun {
		fmt.Println("Dry run...")
	} else {
		fmt.Println("Sending...")
	}

	if config.ExcludePattern != "" {
		fmt.Println("Exclusion check has been enabled.")
	}

	failedUsers := sendToRadius(config, userStats)

	if len(failedUsers) > 0 {
		fmt.Println("\nUnable to send stats for the following user(s):")
		for _, fu := range failedUsers {
			fmt.Printf("  %s (%s)\n", fu.Username, fu.Error)
		}
		os.Exit(1)
	}
}

func parseArgs() *Config {
	config := &Config{}

	flag.StringVar(&config.RadiusServer, "radius-server", "", "RADIUS server address (required)")
	flag.StringVar(&config.RadiusSecret, "radius-secret", "", "RADIUS shared secret (required)")
	flag.IntVar(&config.SeekTime, "seek-time", 60, "time to seek in the log, in minutes")
	flag.StringVar(&config.RadiusAcctPort, "radius-acct-port", "1813", "RADIUS accounting port")
	flag.StringVar(&config.RadiusNASID, "radius-nasid", "nghttpx", "RADIUS NAS Identifier")
	flag.StringVar(&config.NghttpxService, "nghttpx-service", "nghttpx", "systemd service name for nghttpx")
	flag.StringVar(&config.ExcludePattern, "exclude-pattern", "", "do not send to server if username contains this regexp")
	flag.BoolVar(&config.DryRun, "dry-run", false, "run locally only and never contact the server")

	versionFlag := flag.Bool("version", false, "print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("nghttpx2radius %s\n", version)
		os.Exit(0)
	}

	// Validate required flags
	if config.RadiusServer == "" || config.RadiusSecret == "" {
		fmt.Fprintln(os.Stderr, "Error: -radius-server and -radius-secret are required")
		fmt.Fprintln(os.Stderr, "\nUsage: nghttpx2radius [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	return config
}

func analyzeLog(config *Config) map[string]*UserStats {
	// Calculate time range for journald query
	// journald timestamps are in UTC
	cutoffTime := time.Now().UTC().Add(-time.Duration(config.SeekTime) * time.Minute)
	since := cutoffTime.Format("2006-01-02 15:04:05")

	// Run journalctl to get logs from nghttpx service
	cmd := exec.Command("journalctl", "-u", config.NghttpxService, "--since", since, "--no-pager", "-o", "short-iso")
	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to run journalctl: %v", err)
	}

	userStats := make(map[string]*UserStats)
	lines := strings.Split(string(output), "\n")
	lineCount := 0

	// Regex to parse nghttpx log format:
	// $remote_addr - [CN:"$tls_client_subject_name"] [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
	// Example: ::ffff:123.123.123.123 - [CN:"UID=user2,CN=user2"] [12/Nov/2025:14:12:16 +0000] "CONNECT signaler-pa.clients6.google.com:443 HTTP/2" 200 9436 "-" "Mozilla/..."
	logPattern := regexp.MustCompile(`^(\S+)\s+-\s+\[CN:"([^"]+)"\]\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"`)

	for _, line := range lines {
		lineCount++

		if lineCount%10000 == 0 {
			fmt.Print(".")
		}

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Extract the message part from journald output
		// Format: 2025-11-12T14:13:17+0000 localhost nghttpx[5453]: <message>
		parts := strings.SplitN(line, "nghttpx[", 2)
		if len(parts) < 2 {
			continue
		}

		// Extract message after PID
		msgParts := strings.SplitN(parts[1], "]: ", 2)
		if len(msgParts) < 2 {
			continue
		}

		message := msgParts[1]

		// Parse the nghttpx log line
		matches := logPattern.FindStringSubmatch(message)
		if len(matches) < 7 {
			continue
		}

		remoteAddr := matches[1]
		certSubject := matches[2]
		status := matches[5]
		bytesStr := matches[6]

		// Extract username from certificate subject (CN or UID field)
		username := extractUsernameFromSubject(certSubject)
		if username == "" {
			continue
		}

		// Convert IPv4-mapped IPv6 address to pure IPv4
		ipAddr := convertIPv4MappedAddress(remoteAddr)

		// Parse bytes
		bytes, err := strconv.ParseInt(bytesStr, 10, 64)
		if err != nil {
			continue
		}

		// Skip if status is not 200
		if status != "200" {
			continue
		}

		// Initialize user stats if needed
		if userStats[username] == nil {
			userStats[username] = &UserStats{
				BytesByIP:   make(map[string]int64),
				SessionByIP: make(map[string]int64),
			}
		}

		userStats[username].BytesByIP[ipAddr] += bytes
		// For nghttpx, we don't have elapsed time per request, so we use a fixed value
		// This will be capped to 3600 seconds in sendToRadius anyway
		userStats[username].SessionByIP[ipAddr] += 1000 // 1 second in milliseconds
	}

	return userStats
}

// extractUsernameFromSubject extracts the username from the certificate subject.
// Priority: UID field if present, otherwise CN field.
// Example: "emailAddress=user1@home.arpa,CN=user1,OU=Users,O=Lake,L=Tualatin,ST=OR,C=US" -> "user1"
// Example: "UID=user2,CN=user2" -> "user2"
func extractUsernameFromSubject(subject string) string {
	// Split by comma to get individual fields
	fields := strings.Split(subject, ",")

	var cn, uid string

	for _, field := range fields {
		field = strings.TrimSpace(field)
		if strings.HasPrefix(field, "UID=") {
			uid = strings.TrimPrefix(field, "UID=")
		} else if strings.HasPrefix(field, "CN=") {
			cn = strings.TrimPrefix(field, "CN=")
		}
	}

	// Prefer UID over CN
	if uid != "" {
		return uid
	}
	return cn
}

// convertIPv4MappedAddress converts IPv4-mapped IPv6 addresses to pure IPv4.
// Example: "::ffff:123.123.123.123" -> "123.123.123.123"
func convertIPv4MappedAddress(addr string) string {
	// Check if it's an IPv4-mapped IPv6 address
	if strings.HasPrefix(addr, "::ffff:") {
		return strings.TrimPrefix(addr, "::ffff:")
	}
	return addr
}

type FailedUser struct {
	Username string
	Error    string
}

func sendToRadius(config *Config, userStats map[string]*UserStats) []FailedUser {
	var failedUsers []FailedUser

	for username, stats := range userStats {
		fmt.Printf("\t%s\n", username)

		for ip, bytes := range stats.BytesByIP {
			fmt.Printf("\t\t%s\t%s\t", ip, formatBytes(bytes))

			sessionTimeMs := stats.SessionByIP[ip]
			sessionTimeSec := int(sessionTimeMs / 1000)

			// Cap session time at 3600 seconds
			cappedSessionTime := sessionTimeSec
			if cappedSessionTime > 3600 {
				cappedSessionTime = 3600
			}

			fmt.Printf("%d(%d)", cappedSessionTime, sessionTimeSec)

			// Check exclusion pattern
			if config.excludeRegex != nil && config.excludeRegex.MatchString(username) {
				fmt.Println("...skipped!")
				continue
			}

			if config.DryRun {
				fmt.Println()
				continue
			}

			// Send RADIUS accounting packets
			sessionID := fmt.Sprintf("%d", time.Now().Unix())
			err := sendRadiusAccounting(config, username, ip, sessionID, bytes, cappedSessionTime)
			if err != nil {
				failedUsers = append(failedUsers, FailedUser{
					Username: username,
					Error:    err.Error(),
				})
				fmt.Println("FAILED!")
				continue
			}

			fmt.Println()
		}

		fmt.Println("\t---------------------------")
	}

	return failedUsers
}

func sendRadiusAccounting(config *Config, username, ip, sessionID string, bytes int64, sessionTime int) error {
	// Get local IP that routes to RADIUS server
	calledStationIP, err := getCalledStationIP(config.RadiusServer)
	if err != nil {
		return fmt.Errorf("failed to get called station IP: %w", err)
	}

	serverAddr := net.JoinHostPort(config.RadiusServer, config.RadiusAcctPort)

	// Send Accounting-Start
	fmt.Print(".")
	packet := radius.New(radius.CodeAccountingRequest, []byte(config.RadiusSecret))

	rfc2865.UserName_SetString(packet, username)
	rfc2866.AcctSessionID_SetString(packet, sessionID)
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Start)
	rfc2865.NASIdentifier_SetString(packet, config.RadiusNASID)
	rfc2865.CallingStationID_SetString(packet, ip)
	rfc2865.CalledStationID_SetString(packet, calledStationIP)
	// Connect-Info is not in standard radius packages, so we'll skip it for now
	// Or we can add it as a vendor-specific attribute if needed

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = radius.Exchange(ctx, packet, serverAddr)
	if err != nil {
		return fmt.Errorf("failed to send Accounting-Start: %w", err)
	}

	// Send Accounting-Stop
	fmt.Print(".")
	packet = radius.New(radius.CodeAccountingRequest, []byte(config.RadiusSecret))

	rfc2865.UserName_SetString(packet, username)
	rfc2866.AcctSessionID_SetString(packet, sessionID)
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Stop)
	rfc2865.NASIdentifier_SetString(packet, config.RadiusNASID)
	rfc2865.CallingStationID_SetString(packet, ip)
	rfc2865.CalledStationID_SetString(packet, calledStationIP)
	rfc2866.AcctOutputOctets_Set(packet, rfc2866.AcctOutputOctets(bytes))
	rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(sessionTime))
	rfc2866.AcctTerminateCause_Set(packet, rfc2866.AcctTerminateCause_Value_UserRequest)

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = radius.Exchange(ctx, packet, serverAddr)
	if err != nil {
		return fmt.Errorf("failed to send Accounting-Stop: %w", err)
	}

	fmt.Print(".")
	return nil
}

func getCalledStationIP(destIP string) (string, error) {
	// Create a UDP connection to determine the local IP
	conn, err := net.Dial("udp", net.JoinHostPort(destIP, "80"))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

