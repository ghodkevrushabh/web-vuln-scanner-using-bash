#!/bin/bash
#############################################################
# Project      : Web Vulnerability Assessment Tool
# Program      : PGCP-ITISS - Mini Project
# Description  : Passive security audit of a target website -
#                checks headers, SSL/TLS config, exposed
#                sensitive files, open ports, and server
#                fingerprinting. Non-intrusive (no exploits).
# Usage        : ./vuln_scanner.sh example.com
#############################################################

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PASS="[${GREEN}PASS${NC}]"
FAIL="[${RED}FAIL${NC}]"
WARN="[${YELLOW}WARN${NC}]"

# ---------- Input Validation ----------
if [ -z "$1" ]; then
    echo "Usage: $0 <domain-or-url>"
    echo "Example: $0 example.com"
    exit 1
fi

# Strip protocol if user included it, and store clean pieces
RAW_INPUT="$1"
DOMAIN=$(echo "$RAW_INPUT" | sed -E 's~^https?://~~' | cut -d/ -f1)
URL="https://$DOMAIN"

REPORT="vuln_report_${DOMAIN}_$(date +%Y%m%d_%H%M%S).txt"

echo "==============================================================" | tee "$REPORT"
echo " Web Vulnerability Assessment Report" | tee -a "$REPORT"
echo " Target      : $DOMAIN" | tee -a "$REPORT"
echo " Date        : $(date)" | tee -a "$REPORT"
echo "==============================================================" | tee -a "$REPORT"

log()  { echo -e "$1" | tee -a "$REPORT"; }

# ---------- Step 1: Reachability & DNS ----------
log "\n${CYAN}[1] DNS & Reachability Check${NC}"
IP=$(getent hosts "$DOMAIN" | awk '{print $1}' | head -n1)
if [ -z "$IP" ]; then
    IP=$(host "$DOMAIN" 2>/dev/null | awk '/has address/{print $4; exit}')
fi

if [ -n "$IP" ]; then
    log "$PASS Resolved $DOMAIN -> $IP"
else
    log "$FAIL Could not resolve $DOMAIN. Check the domain name and try again."
    exit 1
fi

if curl -s -o /dev/null --max-time 8 "$URL"; then
    log "$PASS Target is reachable over HTTPS"
else
    log "$WARN HTTPS unreachable, will still attempt further checks"
fi

# ---------- Step 2: Port Scan ----------
log "\n${CYAN}[2] Common Port Scan${NC}"
COMMON_PORTS=(21 22 23 25 80 443 3306 8080 8443)
if command -v nmap >/dev/null 2>&1; then
    nmap -Pn -p "$(IFS=,; echo "${COMMON_PORTS[*]}")" "$DOMAIN" 2>/dev/null | tee -a "$REPORT"
else
    log "$WARN nmap not found, falling back to /dev/tcp checks"
    for port in "${COMMON_PORTS[@]}"; do
        (echo > /dev/tcp/"$DOMAIN"/"$port") >/dev/null 2>&1 \
            && log "$WARN Port $port is OPEN" \
            || log "$PASS Port $port is closed/filtered"
    done
fi

# ---------- Step 3: HTTP Security Header Audit ----------
log "\n${CYAN}[3] HTTP Security Header Audit${NC}"
HEADERS=$(curl -s -D - -o /dev/null --max-time 10 "$URL")

check_header () {
    local header_name="$1"
    if echo "$HEADERS" | grep -qi "^$header_name:"; then
        log "$PASS $header_name header present"
    else
        log "$FAIL $header_name header MISSING"
    fi
}

check_header "Strict-Transport-Security"
check_header "Content-Security-Policy"
check_header "X-Frame-Options"
check_header "X-Content-Type-Options"
check_header "Referrer-Policy"
check_header "Permissions-Policy"

# Server / tech disclosure
SERVER_BANNER=$(echo "$HEADERS" | grep -i "^Server:" | tr -d '\r')
POWERED_BY=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | tr -d '\r')

if [ -n "$SERVER_BANNER" ]; then
    log "$WARN Server banner disclosed -> $SERVER_BANNER"
else
    log "$PASS No Server banner disclosed"
fi

if [ -n "$POWERED_BY" ]; then
    log "$WARN Technology disclosed -> $POWERED_BY"
else
    log "$PASS No X-Powered-By disclosure"
fi

# ---------- Step 4: SSL/TLS Audit ----------
log "\n${CYAN}[4] SSL/TLS Configuration Audit${NC}"
if command -v openssl >/dev/null 2>&1; then
    CERT_INFO=$(echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN":443 2>/dev/null)
    EXPIRY=$(echo "$CERT_INFO" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

    if [ -n "$EXPIRY" ]; then
        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

        if [ "$DAYS_LEFT" -lt 0 ]; then
            log "$FAIL SSL certificate EXPIRED on $EXPIRY"
        elif [ "$DAYS_LEFT" -lt 30 ]; then
            log "$WARN SSL certificate expires soon ($DAYS_LEFT days left - $EXPIRY)"
        else
            log "$PASS SSL certificate valid, expires in $DAYS_LEFT days ($EXPIRY)"
        fi
    else
        log "$WARN Could not retrieve certificate expiry"
    fi

    # Check for weak/deprecated protocols
    for proto in ssl2 ssl3 tls1 tls1_1; do
        if echo | openssl s_client -"$proto" -connect "$DOMAIN":443 2>/dev/null | grep -q "CONNECTED"; then
            log "$FAIL Insecure protocol supported: $proto"
        fi
    done
    log "$PASS No SSLv2/SSLv3/TLS1.0/TLS1.1 detected as supported (if none flagged above)"
else
    log "$WARN openssl not found, skipping SSL/TLS audit"
fi

# ---------- Step 5: Sensitive File / Directory Exposure ----------
log "\n${CYAN}[5] Sensitive File & Directory Exposure Check${NC}"
PATHS=(
    "robots.txt"
    ".git/config"
    ".env"
    "admin"
    "backup.zip"
    "config.php.bak"
    "wp-config.php"
    ".htaccess"
    "phpinfo.php"
)

for path in "${PATHS[@]}"; do
    CODE=$(curl -s -o /dev/null --max-time 8 -w "%{http_code}" "$URL/$path")
    if [ "$CODE" == "200" ]; then
        log "$FAIL /$path is ACCESSIBLE (HTTP $CODE) - potential exposure"
    else
        log "$PASS /$path not accessible (HTTP $CODE)"
    fi
done

# ---------- Summary ----------
FAIL_COUNT=$(grep -c "FAIL" "$REPORT")
WARN_COUNT=$(grep -c "WARN" "$REPORT")
PASS_COUNT=$(grep -c "PASS" "$REPORT")

log "\n${CYAN}==================== SUMMARY ====================${NC}"
log "Passed checks : $PASS_COUNT"
log "Warnings      : $WARN_COUNT"
log "Failed checks : $FAIL_COUNT"
log "=================================================="
log "\nFull report saved to: $REPORT"
