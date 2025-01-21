#!/bin/bash From our community!

# Kernel and distribution release details
echo "Kernel and Distribution Release Details:"
uname -a
cat /etc/*release*

# System Information
echo "System Information:"
echo "Hostname: $(hostname)"

# Networking details
echo "Networking Details:"
echo "Current IP:"
ip addr show | grep 'inet '
echo "Default Route Details:"
ip route show
echo "DNS Server Information:"
cat /etc/resolv.conf

# User Information
echo "User Information:"
echo "Current User Details:"
id
echo "Last Logged on Users:"
last
echo "Users Logged onto the Host:"
w
echo "List All Users with UID/GID Information:"
cat /etc/passwd
echo "List Root Accounts:"
grep -E 'root' /etc/passwd
echo "Password Policies and Hash Storage Method Information:"
cat /etc/login.defs | grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|ENCRYPT_METHOD'
echo "UMASK Value:"
umask
echo "Password Hashes Stored in /etc/passwd:"
cat /etc/passwd | grep -E ':x:'
echo "Full Details for 'Default' UIDs (0, 1000, 1001, etc.):"
getent passwd 0 1000 1001
echo "Attempt to Read Restricted Files (e.g., /etc/shadow):"
cat /etc/shadow 2>/dev/null

# Privileged Access
echo "Privileged Access:"
echo "Users Recently Using Sudo:"
cat /var/log/auth.log | grep -E 'sudo|sudo:|COMMAND='
echo "Accessibility of /etc/sudoers:"
ls -l /etc/sudoers
echo "Sudo Access Without Password:"
grep -E '^%sudo|^sudo' /etc/sudoers
echo "Known 'Good' Sudo Binaries:"
grep -E '^sudo|^nmap|^vim|^nano|^vi' /etc/sudoers
echo "Root's Home Directory Accessibility:"
ls -ld /root
echo "Permissions for /home/:"
ls -l /home/

# Environmental
echo "Environmental Information:"
echo "Current PATH:"
echo $PATH
echo "Environment Information:"
env

# Jobs/Tasks
echo "Jobs/Tasks:"
echo "All Cron Jobs:"
ls -l /etc/cron*
echo "World-Writable Cron Jobs:"
find /etc/cron* -type f -perm -002 -exec ls -l {} +
echo "Cron Jobs Owned by Other Users:"
ls -l /etc/cron* | grep -v root

# Services
echo "Services Information:"
echo "List Network Connections (TCP & UDP):"
netstat -tuln
echo "Running Processes:"
ps aux
echo "Process Binaries and Permissions:"
ls -l /proc/*/exe
echo "inetd.conf/xinetd.conf Contents and Binary File Permissions:"
cat /etc/inetd.conf /etc/xinetd.conf
ls -l /usr/sbin/in.* /usr/bin/in.* /etc/xinetd.d/* /etc/inetd.d/*

# Version Information
echo "Version Information:"
echo "Sudo Version:"
sudo --version
echo "MySQL Version:"
mysql --version
echo "PostgreSQL Version:"
psql --version
echo "Apache Version and Configuration:"
apache2 -v
apache2ctl -M
ls /etc/apache2/sites-enabled/
echo "Default/Weak Credentials:"
echo "Default/Weak PostgreSQL Accounts:"
echo "Default/Weak MySQL Accounts:"

# Searches
echo "Searches:"
echo "All SUID/GUID Files:"
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} +
echo "World-Writable SUID/GUID Files:"
find / -type f \( -perm -4002 -o -perm -2002 \) -exec ls -l {} +
echo "SUID/GUID Files Owned by Root:"
find / -user root \( -perm -4000 -o -perm -2000 \) -exec ls -l {} +
echo "Interesting SUID/GUID Files:"
find / -type f \( -perm -4000 -o -perm -2000 \) -exec file {} + | grep -E 'ELF|executable|shared object|dynamic link'
echo "Files with POSIX Capabilities:"
getcap -r / 2>/dev/null
echo "World-Writable Files:"
find / -type f -perm -002 -exec ls -l {} +
echo "Accessible *.plan Files:"
find / -name "*.plan" -exec ls -l {} +
echo "Accessible *.rhosts Files:"
find / -name "*.rhosts" -exec ls -l {} +
echo "NFS Server Details:"
showmount -e

# Platform/Software Specific Tests
echo "Platform/Software Specific Tests:"
echo "Docker Container Check:"
docker info
echo "Docker Installed Check:"
dpkg -l | grep docker
echo "LXC Container Check:"
lxc-checkconfig
