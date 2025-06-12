#!/bin/bash

# System Audit Tool for Linux Servers
# Performs security checks and generates a report with recommendations

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Define output report file
REPORT_FILE="system_audit_report_$(date +%Y%m%d_%H%M%S).txt"
exec 3>&1 1>"$REPORT_FILE"

# Function to print section headers
print_section() {
    echo "==============================================================" >&3
    echo "$1" >&3
    echo "==============================================================" >&3
    echo "=============================================================="
    echo "$1"
    echo "=============================================================="
}

# Function to check open ports
check_open_ports() {
    print_section "Open Ports Check"
    echo "Scanning for open ports using netstat..."
    if command -v netstat >/dev/null; then
        netstat -tuln | grep LISTEN
        echo -e "\nRecommendations:"
        echo "- Review open ports and ensure only necessary services are exposed"
        echo "- Close unused ports using firewall rules (e.g., iptables, ufw)"
        echo "- Consider using a port scanner like nmap for more detailed analysis"
    else
        echo "netstat not found. Please install net-tools package."
    fi
    echo
}

# Function to check file permissions
check_file_permissions() {
    print_section "File Permissions Check"
    echo "Checking for world-writable files..."
    find / -type f -perm -o+w -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | while read -r file; do
        echo "World-writable file: $file"
        ls -l "$file"
    done
    echo -e "\nChecking for sensitive files with weak permissions..."
    sensitive_files=("/etc/passwd" "/etc/shadow" "/etc/ssh/sshd_config")
    for file in "${sensitive_files[@]}"; do
        if [ -f "$file" ]; then
            perms=$(stat -c "%a" "$file")
            echo "$file permissions: $perms"
            if [ "$file" = "/etc/shadow" ] && [ "$perms" -gt 600 ]; then
                echo "WARNING: $file has overly permissive permissions"
            elif [ "$file" != "/etc/shadow" ] && [ "$perms" -gt 644 ]; then
                echo "WARNING: $file has overly permissive permissions"
            fi
        fi
    done
    echo -e "\nRecommendations:"
    echo "- Remove world-writable permissions (chmod o-w <file>)"
    echo "- Set appropriate permissions for sensitive files (e.g., chmod 600 /etc/shadow, chmod 644 /etc/passwd)"
    echo "- Regularly audit file permissions using tools like find or stat"
    echo
}

# Function to check unauthorized users
check_users() {
    print_section "User Account Check"
    echo "Checking for users with UID 0 (root privileges)..."
    awk -F: '$3 == 0 {print $1}' /etc/passwd | while read -r user; do
        echo "User with UID 0: $user"
        [ "$user" != "root" ] && echo "WARNING: Non-root user with UID 0 detected"
    done
    echo -e "\nChecking for users with empty passwords..."
    awk -F: '($2 == "") {print $1}' /etc/shadow | while read -r user; do
        echo "User with empty password: $user"
    done
    echo -e "\nRecommendations:"
    echo "- Remove or modify unauthorized users with UID 0"
    echo "- Set passwords for accounts with empty passwords (passwd <user>)"
    echo "- Regularly review /etc/passwd and /etc/shadow for anomalies"
    echo
}

# Function to check for outdated software
check_software_updates() {
    print_section "Software Updates Check"
    if command -v apt >/dev/null; then
        echo "Checking for available updates (Debian/Ubuntu)..."
        apt update >/dev/null 2>&1
        apt list --upgradable 2>/dev/null
    elif command -v yum >/dev/null; then
        echo "Checking for available updates (CentOS/RHEL)..."
        yum check-update
    else
        echo "Package manager not recognized. Please check updates manually."
    fi
    echo -e "\nChecking kernel version..."
    uname -r
    echo -e "\nRecommendations:"
    echo "- Apply all available security updates (apt upgrade or yum update)"
    echo "- Monitor for kernel updates and apply them promptly"
    echo "- Subscribe to security mailing lists for your distribution"
    echo
}

# Function to check for password security issues
check_password_security() {
    print_section "Password Security Check"
    
    echo "Checking /etc/shadow file permissions and ownership..."
    if [ -f "/etc/shadow" ]; then
        shadow_perms=$(stat -c "%a" /etc/shadow)
        shadow_owner=$(stat -c "%U:%G" /etc/shadow)
        echo "/etc/shadow permissions: $shadow_perms"
        echo "/etc/shadow ownership: $shadow_owner"
        
        if [ "$shadow_perms" -gt 600 ]; then
            echo "CRITICAL: /etc/shadow has overly permissive permissions ($shadow_perms)"
        fi
        
        if [ "$shadow_owner" != "root:shadow" ] && [ "$shadow_owner" != "root:root" ]; then
            echo "CRITICAL: /etc/shadow has incorrect ownership ($shadow_owner)"
        fi
    else
        echo "WARNING: /etc/shadow file not found"
    fi
    
    echo -e "\nChecking for weak password hashing algorithms..."
    if [ -f "/etc/shadow" ]; then
        # Check for password hashing algorithms (DES, MD5)
        des_count=$(grep -c ':\$1\$' /etc/shadow)
        md5_count=$(grep -c ':\$5\$' /etc/shadow)
        
        if [ "$des_count" -gt 0 ]; then
            echo "CRITICAL: $des_count accounts using weak DES password hashing"
        fi
        
        if [ "$md5_count" -gt 0 ]; then
            echo "WARNING: $md5_count accounts using MD5 password hashing"
        fi
    fi
    
    echo -e "\nChecking for default or common passwords..."
    # Check for common default passwords in /etc/shadow (if we can read it)
    if [ -r "/etc/shadow" ]; then
        # Check for common password hashes (this is simplified)
        if grep -q ':\$6\$.*:' /etc/shadow; then
            echo "NOTE: SHA-512 password hashing in use (recommended)"
        fi
        
        # Check for accounts with no password but can login
        no_pass_accounts=$(awk -F: '($2 == "" || $2 == "*" || $2 == "!") && $3 >= 1000 {print $1}' /etc/shadow)
        if [ -n "$no_pass_accounts" ]; then
            echo "WARNING: The following accounts have no password set:"
            echo "$no_pass_accounts"
        fi
    else
        echo "NOTE: Cannot read /etc/shadow for detailed password analysis (normal if not root)"
    fi
    
    echo -e "\nChecking for plaintext passwords in common config files..."
    config_files=(
        "/etc/fstab"
        "/etc/apache2/httpd.conf"
        "/etc/nginx/nginx.conf"
        "/etc/ssh/sshd_config"
        "/home/*/.bash_history"
        "/root/.bash_history"
        "/var/www/html/*.php"
        "/var/www/html/*.conf"
        "/etc/*.conf"
    )
    
    echo "Searching for potential plaintext passwords in config files..."
    for pattern in "password" "passwd" "pwd" "secret" "credentials"; do
        for file in "${config_files[@]}"; do
            if [ -f "$file" ] || [ -d "$(dirname "$file")" ]; then
                # Use grep with context to find potential password lines
                matches=$(grep -l "$pattern" $file 2>/dev/null)
                if [ -n "$matches" ]; then
                    echo "Potential plaintext password in: $matches"
                fi
            fi
        done
    done
    
    echo -e "\nChecking password policies..."
    if [ -f "/etc/pam.d/common-password" ]; then
        if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            echo "Password quality requirements are configured"
        else
            echo "WARNING: No password quality requirements found"
        fi
    fi
    
    if [ -f "/etc/login.defs" ]; then
        pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
        if [ -n "$pass_max_days" ] && [ "$pass_max_days" -gt 90 ]; then
            echo "WARNING: Password expiration too long: $pass_max_days days"
        elif [ -z "$pass_max_days" ]; then
            echo "WARNING: Password expiration not set"
        else
            echo "Password expiration set to $pass_max_days days"
        fi
    fi
    
    echo -e "\nRecommendations:"
    echo "- Ensure /etc/shadow has 0600 permissions and root:shadow ownership"
    echo "- Use strong password hashing algorithms (SHA-512 or better)"
    echo "- Implement password complexity requirements via PAM"
    echo "- Set appropriate password expiration policies"
    echo "- Remove any plaintext passwords from configuration files"
    echo "- Consider using a password manager for application credentials"
    echo "- Implement multi-factor authentication where possible"
    echo
}

# Main function to run all checks
main() {
    echo "System Audit Report" >&3
    echo "Generated on: $(date)" >&3
    echo "Hostname: $(hostname)" >&3
    echo >&3
    check_open_ports
    check_file_permissions
    check_users
    check_software_updates
    check_password_security
    print_section "Audit Complete"
    echo "Report saved to: $REPORT_FILE" >&3
    echo "Please review the recommendations and take appropriate actions." >&3
}

# Execute main function
main

# Close file descriptor
exec 1>&3 3>&-
