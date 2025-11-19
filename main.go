package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

const version = "5.0.0"

type Config struct {
	RadiusServer     string
	RadiusSecret     string
	RadiusAcctPort   string
	RadiusNASID      string
	NghttpxService   string
	ExcludePattern   string
	InterimInterval  int  // minutes
	DryRun           bool
	excludeRegex     *regexp.Regexp
}

// Session represents an active accounting session
type Session struct {
	Username        string
	IP              string
	SessionID       string
	FirstSeen       time.Time
	LastSeen        time.Time
	LastUpdate      time.Time
	TotalBytes      int64
	CalledStationIP string
	mu              sync.Mutex
}

// SessionManager manages all active sessions
type SessionManager struct {
	sessions map[string]*Session // key: username:ip
	mu       sync.RWMutex
	config   *Config
	logger   *log.Logger
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

	// Initialize syslog logger
	syslogger, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "nghttpx2radius")
	if err != nil {
		log.Fatalf("Failed to initialize syslog: %v", err)
	}
	defer syslogger.Close()

	logger := log.New(syslogger, "", 0)
	logger.Printf("nghttpx2radius daemon v%s starting", version)

	if config.DryRun {
		logger.Println("Running in DRY RUN mode")
	}

	// Create session manager
	sm := NewSessionManager(config, logger)

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// Start background workers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start log monitor
	go sm.monitorLogs(ctx)

	// Start session checker (for interim updates and timeouts)
	go sm.sessionChecker(ctx)

	logger.Println("Daemon started successfully")

	// Wait for shutdown signal
	sig := <-sigChan
	logger.Printf("Received signal %v, shutting down gracefully", sig)

	// Cancel context to stop workers
	cancel()

	// Close all active sessions
	sm.closeAllSessions()

	logger.Println("Daemon stopped")
}

func parseArgs() *Config {
	config := &Config{}

	flag.StringVar(&config.RadiusServer, "radius-server", "", "RADIUS server address (required)")
	flag.StringVar(&config.RadiusSecret, "radius-secret", "", "RADIUS shared secret (required)")
	flag.StringVar(&config.RadiusAcctPort, "radius-acct-port", "1813", "RADIUS accounting port")
	flag.StringVar(&config.RadiusNASID, "radius-nasid", "nghttpx", "RADIUS NAS Identifier")
	flag.StringVar(&config.NghttpxService, "nghttpx-service", "nghttpx", "systemd service name for nghttpx")
	flag.StringVar(&config.ExcludePattern, "exclude-pattern", "", "do not send to server if username contains this regexp")
	flag.IntVar(&config.InterimInterval, "interim-interval", 15, "interim update interval in minutes")
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

	if config.InterimInterval < 1 {
		fmt.Fprintln(os.Stderr, "Error: -interim-interval must be at least 1 minute")
		os.Exit(1)
	}

	return config
}

// NewSessionManager creates a new session manager
func NewSessionManager(config *Config, logger *log.Logger) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		config:   config,
		logger:   logger,
	}
}

// monitorLogs continuously monitors journald logs for new entries
func (sm *SessionManager) monitorLogs(ctx context.Context) {
	sm.logger.Printf("Starting log monitor for service: %s", sm.config.NghttpxService)

	// Regex to parse nghttpx log format
	logPattern := regexp.MustCompile(`^(\S+)\s+-\s+\[CN:"([^"]+)"\]\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"`)

	for {
		select {
		case <-ctx.Done():
			sm.logger.Println("Log monitor stopping")
			return
		default:
		}

		// Follow journald logs in real-time
		cmd := exec.CommandContext(ctx, "journalctl", "-u", sm.config.NghttpxService, "-f", "-n", "0", "-o", "short-iso")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			sm.logger.Printf("Error creating stdout pipe: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if err := cmd.Start(); err != nil {
			sm.logger.Printf("Error starting journalctl: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			sm.processLogLine(line, logPattern)
		}

		if err := scanner.Err(); err != nil {
			sm.logger.Printf("Error reading log: %v", err)
		}

		cmd.Wait()
		sm.logger.Println("journalctl process ended, restarting...")
		time.Sleep(2 * time.Second)
	}
}

// processLogLine parses a log line and updates or creates sessions
func (sm *SessionManager) processLogLine(line string, logPattern *regexp.Regexp) {
	// Extract the message part from journald output
	parts := strings.SplitN(line, "nghttpx[", 2)
	if len(parts) < 2 {
		return
	}

	msgParts := strings.SplitN(parts[1], "]: ", 2)
	if len(msgParts) < 2 {
		return
	}

	message := msgParts[1]

	// Parse the nghttpx log line
	matches := logPattern.FindStringSubmatch(message)
	if len(matches) < 7 {
		return
	}

	remoteAddr := matches[1]
	certSubject := matches[2]
	status := matches[5]
	bytesStr := matches[6]

	// Skip if status is not 200
	if status != "200" {
		return
	}

	// Extract username from certificate subject
	username := extractUsernameFromSubject(certSubject)
	if username == "" {
		return
	}

	// Check exclusion pattern
	if sm.config.excludeRegex != nil && sm.config.excludeRegex.MatchString(username) {
		return
	}

	// Convert IPv4-mapped IPv6 address to pure IPv4
	ipAddr := convertIPv4MappedAddress(remoteAddr)

	// Parse bytes
	bytes, err := strconv.ParseInt(bytesStr, 10, 64)
	if err != nil {
		return
	}

	// Update or create session
	sm.updateSession(username, ipAddr, bytes)
}

// updateSession updates an existing session or creates a new one
func (sm *SessionManager) updateSession(username, ip string, bytes int64) {
	sessionKey := fmt.Sprintf("%s:%s", username, ip)

	sm.mu.Lock()
	session, exists := sm.sessions[sessionKey]

	if !exists {
		// Create new session
		calledStationIP, err := getCalledStationIP(sm.config.RadiusServer)
		if err != nil {
			sm.logger.Printf("Failed to get called station IP: %v", err)
			sm.mu.Unlock()
			return
		}

		session = &Session{
			Username:        username,
			IP:              ip,
			SessionID:       fmt.Sprintf("%d", time.Now().Unix()),
			FirstSeen:       time.Now(),
			LastSeen:        time.Now(),
			LastUpdate:      time.Now(),
			TotalBytes:      bytes,
			CalledStationIP: calledStationIP,
		}
		sm.sessions[sessionKey] = session
		sm.mu.Unlock()

		sm.logger.Printf("New session: %s from %s", username, ip)

		// Send Accounting-Start
		if err := sm.sendRadiusStart(session); err != nil {
			sm.logger.Printf("Failed to send Accounting-Start for %s: %v", sessionKey, err)
		}
	} else {
		sm.mu.Unlock()

		// Update existing session
		session.mu.Lock()
		session.LastSeen = time.Now()
		session.TotalBytes += bytes
		session.mu.Unlock()
	}
}

// sessionChecker periodically checks sessions for interim updates and timeouts
func (sm *SessionManager) sessionChecker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	sm.logger.Printf("Session checker started (interim interval: %d minutes)", sm.config.InterimInterval)

	for {
		select {
		case <-ctx.Done():
			sm.logger.Println("Session checker stopping")
			return
		case <-ticker.C:
			sm.checkSessions()
		}
	}
}

// checkSessions checks all sessions for updates and timeouts
func (sm *SessionManager) checkSessions() {
	now := time.Now()
	interimDuration := time.Duration(sm.config.InterimInterval) * time.Minute

	sm.mu.RLock()
	sessionsCopy := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessionsCopy = append(sessionsCopy, session)
	}
	sm.mu.RUnlock()

	for _, session := range sessionsCopy {
		session.mu.Lock()
		lastSeen := session.LastSeen
		lastUpdate := session.LastUpdate
		session.mu.Unlock()

		// Check if session has timed out (no activity for interim interval)
		if now.Sub(lastSeen) >= interimDuration {
			sm.logger.Printf("Session timeout: %s from %s", session.Username, session.IP)
			sm.closeSession(session)
		} else if now.Sub(lastUpdate) >= interimDuration {
			// Send interim update
			sm.logger.Printf("Interim update: %s from %s", session.Username, session.IP)
			if err := sm.sendRadiusInterim(session); err != nil {
				sm.logger.Printf("Failed to send Interim-Update: %v", err)
			} else {
				session.mu.Lock()
				session.LastUpdate = now
				session.mu.Unlock()
			}
		}
	}
}

// closeSession closes a session and sends Accounting-Stop
func (sm *SessionManager) closeSession(session *Session) {
	sessionKey := fmt.Sprintf("%s:%s", session.Username, session.IP)

	sm.mu.Lock()
	delete(sm.sessions, sessionKey)
	sm.mu.Unlock()

	if err := sm.sendRadiusStop(session); err != nil {
		sm.logger.Printf("Failed to send Accounting-Stop for %s: %v", sessionKey, err)
	}
}

// closeAllSessions closes all active sessions
func (sm *SessionManager) closeAllSessions() {
	sm.logger.Println("Closing all active sessions")

	sm.mu.Lock()
	sessionsCopy := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessionsCopy = append(sessionsCopy, session)
	}
	sm.sessions = make(map[string]*Session)
	sm.mu.Unlock()

	for _, session := range sessionsCopy {
		if err := sm.sendRadiusStop(session); err != nil {
			sm.logger.Printf("Failed to send Accounting-Stop for %s:%s: %v", session.Username, session.IP, err)
		}
	}

	sm.logger.Printf("Closed %d sessions", len(sessionsCopy))
}

// sendRadiusStart sends an Accounting-Start packet
func (sm *SessionManager) sendRadiusStart(session *Session) error {
	if sm.config.DryRun {
		sm.logger.Printf("[DRY-RUN] Would send Accounting-Start for %s from %s", session.Username, session.IP)
		return nil
	}

	packet := radius.New(radius.CodeAccountingRequest, []byte(sm.config.RadiusSecret))
	rfc2865.UserName_SetString(packet, session.Username)
	rfc2866.AcctSessionID_SetString(packet, session.SessionID)
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Start)
	rfc2865.NASIdentifier_SetString(packet, sm.config.RadiusNASID)
	rfc2865.CallingStationID_SetString(packet, session.IP)
	rfc2865.CalledStationID_SetString(packet, session.CalledStationIP)

	// Add Connect-Info (RFC 2869, Attribute 77)
	if attr, err := radius.NewString("HTTPS Proxy"); err == nil {
		packet.Add(77, attr)
	}

	serverAddr := net.JoinHostPort(sm.config.RadiusServer, sm.config.RadiusAcctPort)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := radius.Exchange(ctx, packet, serverAddr)
	if err != nil {
		return fmt.Errorf("Accounting-Start failed: %w", err)
	}

	sm.logger.Printf("Sent Accounting-Start for %s from %s (session: %s)", session.Username, session.IP, session.SessionID)
	return nil
}

// sendRadiusInterim sends an Interim-Update packet
func (sm *SessionManager) sendRadiusInterim(session *Session) error {
	session.mu.Lock()
	sessionTime := int(time.Since(session.FirstSeen).Seconds())
	totalBytes := session.TotalBytes
	session.mu.Unlock()

	if sm.config.DryRun {
		sm.logger.Printf("[DRY-RUN] Would send Interim-Update for %s from %s (bytes: %d, time: %d)", session.Username, session.IP, totalBytes, sessionTime)
		return nil
	}

	packet := radius.New(radius.CodeAccountingRequest, []byte(sm.config.RadiusSecret))
	rfc2865.UserName_SetString(packet, session.Username)
	rfc2866.AcctSessionID_SetString(packet, session.SessionID)
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_InterimUpdate)
	rfc2865.NASIdentifier_SetString(packet, sm.config.RadiusNASID)
	rfc2865.CallingStationID_SetString(packet, session.IP)
	rfc2865.CalledStationID_SetString(packet, session.CalledStationIP)
	rfc2866.AcctOutputOctets_Set(packet, rfc2866.AcctOutputOctets(totalBytes))
	rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(sessionTime))

	serverAddr := net.JoinHostPort(sm.config.RadiusServer, sm.config.RadiusAcctPort)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := radius.Exchange(ctx, packet, serverAddr)
	if err != nil {
		return fmt.Errorf("Interim-Update failed: %w", err)
	}

	sm.logger.Printf("Sent Interim-Update for %s from %s (bytes: %d, time: %ds)", session.Username, session.IP, totalBytes, sessionTime)
	return nil
}

// sendRadiusStop sends an Accounting-Stop packet
func (sm *SessionManager) sendRadiusStop(session *Session) error {
	session.mu.Lock()
	sessionTime := int(time.Since(session.FirstSeen).Seconds())
	totalBytes := session.TotalBytes
	session.mu.Unlock()

	if sm.config.DryRun {
		sm.logger.Printf("[DRY-RUN] Would send Accounting-Stop for %s from %s (bytes: %d, time: %d)", session.Username, session.IP, totalBytes, sessionTime)
		return nil
	}

	packet := radius.New(radius.CodeAccountingRequest, []byte(sm.config.RadiusSecret))
	rfc2865.UserName_SetString(packet, session.Username)
	rfc2866.AcctSessionID_SetString(packet, session.SessionID)
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Stop)
	rfc2865.NASIdentifier_SetString(packet, sm.config.RadiusNASID)
	rfc2865.CallingStationID_SetString(packet, session.IP)
	rfc2865.CalledStationID_SetString(packet, session.CalledStationIP)
	rfc2866.AcctOutputOctets_Set(packet, rfc2866.AcctOutputOctets(totalBytes))
	rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(sessionTime))
	rfc2866.AcctTerminateCause_Set(packet, rfc2866.AcctTerminateCause_Value_UserRequest)

	serverAddr := net.JoinHostPort(sm.config.RadiusServer, sm.config.RadiusAcctPort)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := radius.Exchange(ctx, packet, serverAddr)
	if err != nil {
		return fmt.Errorf("Accounting-Stop failed: %w", err)
	}

	sm.logger.Printf("Sent Accounting-Stop for %s from %s (bytes: %d, time: %ds, session: %s)", session.Username, session.IP, totalBytes, sessionTime, session.SessionID)
	return nil
}

// extractUsernameFromSubject extracts the username from the certificate subject.
// Handles multiple formats:
// - Simple username: "user1" -> "user1"
// - Comma-separated DN: "UID=user1,CN=user1" -> "user1"
// - Slash-separated DN: "/CN=user1/UID=user1" -> "user1"
// - Full DN: "emailAddress=user1@home.arpa,CN=user1,OU=Users,O=Lake,L=Tualatin,ST=OR,C=US" -> "user1"
// Priority: UID field if present, otherwise CN field, otherwise the whole subject if no DN fields found
func extractUsernameFromSubject(subject string) string {
	// If subject doesn't contain '=' or '/', it's a simple username
	if !strings.Contains(subject, "=") && !strings.Contains(subject, "/") {
		return subject
	}

	var cn, uid string

	// Handle slash-separated DN format (e.g., "/CN=user1/UID=user1")
	if strings.HasPrefix(subject, "/") {
		fields := strings.Split(subject, "/")
		for _, field := range fields {
			field = strings.TrimSpace(field)
			if strings.HasPrefix(field, "UID=") {
				uid = strings.TrimPrefix(field, "UID=")
			} else if strings.HasPrefix(field, "CN=") {
				cn = strings.TrimPrefix(field, "CN=")
			}
		}
	} else {
		// Handle comma-separated DN format (e.g., "UID=user1,CN=user1")
		fields := strings.Split(subject, ",")
		for _, field := range fields {
			field = strings.TrimSpace(field)
			if strings.HasPrefix(field, "UID=") {
				uid = strings.TrimPrefix(field, "UID=")
			} else if strings.HasPrefix(field, "CN=") {
				cn = strings.TrimPrefix(field, "CN=")
			}
		}
	}

	// Prefer UID over CN
	if uid != "" {
		return uid
	}
	if cn != "" {
		return cn
	}

	// If no UID or CN found, return the original subject
	return subject
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

