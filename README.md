<p align="center">
<img src="https://github.com/DannnyzZ/Scripted-Linux-Hardening-SLH-/blob/be753fa910e769c2554528c3d35098f8ce906977/Scripted%20Linux%20Hardening%20(SLH)_Background.png" >
</p>

## Scripted Linux Hardening (SLH) v.1.0 UNDER DEVELOPMENT

<p align="center">
  <img src="https://img.shields.io/badge/Linux-blue?style=for-the-badge&logo=Linux&logoColor=blue&labelColor=white" />
  <img src="https://img.shields.io/badge/Bash-gold?style=for-the-badge&logo=Bash&logoColor=red" />
  <img src="https://img.shields.io/badge/NIST-orange?style=for-the-badge&logo=nist&logoColor=white" />
  <img src="https://img.shields.io/badge/CIS-purple?style=for-the-badge&logo=cis&logoColor=white" />
  <img src="https://img.shields.io/badge/Red%20Hat-red?style=for-the-badge&logo=red-hat&logoColor=red&labelColor=white" />
  <img src="https://img.shields.io/badge/OSHardening-black?style=for-the-badge" />
</p>

About SLH - WRITE HERE

Hardening guidelines were based on:

`Red Hat: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/security_guide/index`

`Center for Internet Security (CIS): https://www.cisecurity.org/cis-benchmarks`

`National Institute of Standards and Technology (NIST): https://ncp.nist.gov/checklist/909`

`SSH.com: https://www.ssh.com/academy/ssh/sshd_config`

---


## 📒 Table of Contents
- [📍 Overview](#-overview)
- [📋 Sectors of Hardening](#-sectors-of-hardening)
  - [🛠️ System Maintenance](#%EF%B8%8F-system-maintenance)
  - [👨‍💼 Accounts](#-accounts)
  - [🔳 Kernel](#-kernel)
  - [🗃️ File System](#%EF%B8%8F-file-system)
  - [🧾 Logging, Monitoring & Alerting](#-logging-monitoring--alerting)
  - [🌐 Network & Services](#-network--services)
  - [📛 Firewall & Security](#-firewall--security)
- [🚀 Getting Started](#-getting-started)
  - [✔️ Prerequisites](#️-prerequisites)
  - [⚠️ Warning](#-Warning)
- [🗺 Roadmap](#-roadmap)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [👏 Acknowledgments](#-acknowledgments)
- [🗃️ Changelog](#%EF%B8%8F-changelog)


---


# 📍 Overview


Write here


# 🛠️ System Maintenance

1. Update distribution.
2. Update system and services.
3. Remove unnecessary libraries.
4. Set automatic updates on every boot.

### Unattended-upgrades 

Unattended-upgrades is a package available on Linux systems that automates the process of installing security updates. It is commonly used to keep the operating system and installed software up-to-date with the latest security patches.

```sh
# Install unattended-upgrades for automatic updates
sudo apt-get install unattended-upgrades

# Create the following file to configure the update settings
echo 'APT::Periodic::Update-Package-Lists "1";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades

# Enable automatic updates
sudo dpkg-reconfigure --priority=low unattended-upgrades

# Update distribution (might cause problem with used apt process)
sudo apt dist-upgrade

# Update system and services
sudo apt update && sudo apt upgrade

# Removal of unnecessary libraries
sudo apt-get autoremove && sudo apt-get autoremove --purge
```


# 👨‍💼 Accounts
1. Password policies
- Password age
- Password complexity requirements
- Implement multi-factor authentication where possible.
2. Account restrictions for regular user
- Disable execution, let write and read contents.
- Disable system paths.
- Establish the least privilege.

Paths/Directories required for workstation user to work properly: 


### Main syntax
```sh
# Set the minimum password length to 12 characters
echo "password requisite pam_pwquality.so minlen=12" | sudo tee -a /etc/pam.d/sshd
# Require at least one uppercase letter in passwords
echo "password requisite pam_pwquality.so ucredit=-1" | sudo tee -a /etc/pam.d/sshd
# Require at least one lowercase letter in passwords
echo "password requisite pam_pwquality.so lcredit=-1" | sudo tee -a /etc/pam.d/sshd
# Require at least one digit in passwords
echo "password requisite pam_pwquality.so dcredit=-1" | sudo tee -a /etc/pam.d/sshd
# Require at least one special character in passwords
echo "password requisite pam_pwquality.so ocredit=-1" | sudo tee -a /etc/pam.d/sshd
# Enforce password history, preventing reuse of the last 5 passwords
echo "password requisite pam_pwhistory.so remember=5" | sudo tee -a /etc/pam.d/sshd
# Lock accounts after a defined number of unsuccessful login attempts
echo "auth required pam_tally2.so deny=6 unlock_time=1200" | sudo tee -a /etc/pam.d/common-auth

# Reload the PAM configuration
sudo pam-auth-update
# Restart the service
sudo systemctl restart sshd
```


# 🔳 Kernel
1. Automatic update and upgrade of software.
2. GRUB password protection.
3. Secure Bootloader/GRUB directory


```sh
# 1. Generate a hashed password (MY_NEW_HASH) and capture it for user to be authorized (MY_SUDO_USER)
sudo grub-mkpasswd-pbkdf2
# 2. Open the GRUB configuration file for editing
sudo nano /etc/grub.d/40_custom 
# 3. Edit values (replace 'MY_SUDO_USER' and 'MY_SUDO_HASH' with your values)
echo 'set superusers="MY_SUDO_USER"' | sudo tee -a /etc/grub.d/40_custom
echo 'password_pbkdf2 MY_SUDO_USER MY_SUDO_HASH' | sudo tee -a /etc/grub.d/40_custom
# 4. Update GRUB
sudo update-grub


# Set the owner of the /boot directory to the root user and root group.
sudo chown root:root /boot
# Restrict permissions on the /boot directory to only allow the root user full access (read, write, and execute).
sudo chmod 700 /boot
```


# 🗃️ File System
1. Implement proper file system permissions.
   - change owner of directories to root
   - change permissions (the least privilege)
3. Utilize file system encryption for sensitive data.

```sh
# Set the owner of the /boot directory to the root user and root group.
sudo chown root:root /root
# Restrict permissions on the /boot directory to only allow the root user full access (read, write, and execute).
sudo chmod 700 /root

# Restrict access to system binaries
sudo chown root:root /bin
sudo chmod 711 /bin
sudo chown root:root /sbin
sudo chmod 711 /sbin
sudo chown root:root /usr/bin
sudo chmod 755 /usr/bin
sudo chown root:root /usr/sbin
sudo chmod 755 /usr/sbin

# Restrict access to system libraries
sudo chown root:root /lib
sudo chmod 755 /lib
sudo chown root:root /lib64
sudo chmod 755 /lib64

# Restrict access to system configuration files
sudo chown root:root /etc
sudo chmod 755 /etc

# Restrict access to kernel and boot-related files
sudo chown root:root /boot
sudo chmod 700 /boot

# Restrict access to system log files
sudo chown root:root /var/log
sudo chmod 755 /var/log

# Restrict access to temporary directories
sudo chown root:root /tmp
sudo chmod 1777 /tmp
sudo chown root:root /var/tmp
sudo chmod 1777 /var/tmp
```


---


# 🧾 Logging, Monitoring & Alerting
1. Implement centralized logging for better analysis.
2. Adjust logging level to fit needs.

<details closed><summary>Event Log Categories</summary>

| Severity Level | Description |
|---|---|
| Emergency (emerg) | System is unusable. |
| Alert (alert) | Action must be taken immediately. |
| Critical (crit) | Critical conditions. |
| Error (err) | Error conditions. |
| Warning (warning) | Warning conditions. |
| Notice (notice) | Normal but significant condition. |
| Informational (info) | Informational messages. |
| Debug (debug) | Debug-level messages. |

</details>

### Event Log Categories

<details closed><summary>Event Log Categories</summary>

| Event Log | General Category | Specific Events |
|---|---|---|
| auth,authpriv.* | Authentication, Authorization, Access Control | Successful logins, failed logins, password changes, account lockouts, account unlocks, account modifications, privilege escalation, root logins, Sudo usage |
| log-emergency | High-Priority Security Events | Kernel panics, system crashes, data corruption, malware infections, denial-of-service attacks, brute-force attacks, unauthorized access |
| cron.* | System Scheduling and Execution | Cron job failures, cron job timeouts, cron job collisions, cron job race conditions, cron job misconfiguration |
| daemon.* | System Services and Processes | Service startups, service shutdowns, service errors, process restarts, process crashes, process hangs, process memory leaks |
| user.* | User-Related Activities | User account creations, user account deletions, user account modifications, user password changes, user group changes, user home directory changes |
| kern.* | System Kernel and Hardware Events | Hardware errors, software errors, system calls, interrupts, memory management, process management |
| lpr.* | Printing and Printer-Related Activities | Print job submissions, print job failures, print job errors, print job status changes, print queue management |
| mail.* | Mail and Email Server Activity | Email sent, email received, email errors, email delivery failures, email content filtering, email security scanning |

</details>

### Rsyslog

Rsyslog is a versatile and powerful system logging daemon for Linux and Unix-like systems. It's widely used for collecting, aggregating, and routing system log messages from various sources, such as daemons, applications, and services.

1. Install rsyslog:
```sh
# Install rsyslog
sudo apt install rsyslog
```

2. Configure rsyslog with severity levels:
```sh
# Authentication, Authorization, Access Control
ifFacility AUTHPRIV auth,authpriv.* ifSeverity >= info /var/log/auth.log
# High-Priority Security Events
ifSeverity !emerg.* log-emergency /var/log/emergency.log
# System Scheduling and Execution
ifSeverity !emerg.* daemon.* ifSeverity >= info /var/log/daemon.log
# User-Related Activities
ifSeverity !emerg.* user.* ifSeverity >= info /var/log/user.log
# System Kernel and Hardware Events
ifSeverity !emerg.* kern.* ifSeverity >= info /var/log/kern.log
# Printing and Printer-Related Activities
ifSeverity !emerg.* lpr.* ifSeverity >= info /var/log/lpr.log
# Mail and Email Server Activity
ifSeverity !emerg.* mail.* ifSeverity >= info /var/log/mail.log

# Restart rsyslog
sudo service rsyslog restart
```


---


# 🌐 Network & Services
1. Configure and maintain firewall rules using tools like iptables.
### Default syntax
```sh
1. Disable and/or uninstall unnecessary network services.
- Check status of service
systemctl status <service_name>
systemctl show --property=ActiveState --property=SubState <service_name>
- Get info about package
systemctl list-unit-files | grep <package_name>
- Stop, disable, uninstall service, remove its package.
sudo systemctl stop <service_name> && sudo apt remove --purge --auto-remove -y <package_name>
```
### Services to stop:

<details closed><summary>Services</summary>

| Service       | Details                                                        |
| ------------- | -------------------------------------------------------------- |
| Telnet        | Protocol: N/A. Function: Telnet provides remote terminal access to a host. Security: Insecure due to plaintext transmission of data, susceptible to man-in-the-middle attacks; use secure alternatives like SSH.               |
| Rlogin        | Protocol: N/A. Function: Rlogin allows remote login to a host. Security: Insecure, transmits data in plaintext; consider using more secure alternatives like SSH.                              |
| Rsh           | Protocol: N/A. Function: Rsh enables remote shell access. Security: Insecure, lacks encryption; use secure alternatives such as SSH to protect remote shell sessions.                          |
| Vsftpd        | Protocol: FTP. Function: Vsftpd is an FTP server. Security: Secure if configured properly with appropriate access controls and encryption; regularly update for the latest security patches.                  |
| Finger        | Protocol: N/A. Function: Finger is used for user information lookup on a remote system. Security: Generally insecure, often disabled due to privacy and security concerns; not recommended for modern systems.     |
| Authd         | Protocol: N/A. Function: Authd is an authentication daemon responsible for user authentication. Security: Security depends on the specific implementation and configuration; ensure it is configured securely.         |
| Netdump       | Protocol: N/A. Function: Netdump facilitates the collection of network crash dumps in case of system failures. Security: Configure securely, limit access to authorized systems, and encrypt collected data if sensitive.      |
| Netdump-Server| Protocol: N/A. Function: Netdump-Server is a network crash dump server. Security: Configure securely, limit access to authorized systems, and encrypt collected data if sensitive.           |
| NFS           | Protocol: NFS. Function: NFS (Network File System) allows remote file access over a network. Security: Secure with proper configuration, access controls, and the use of NFSv4 with strong authentication mechanisms.                 |
| Rwhod         | Protocol: N/A. Function: Rwhod is a daemon that maintains a central database of who is logged into the network. Security: Insecure; consider alternatives or secure configurations, and limit access to authorized systems.               |
| Sendmail      | Protocol: SMTP. Function: Sendmail is a widely-used mail transfer agent (MTA) for sending and receiving email. Security: Secure with proper configuration, regular updates, and adherence to security best practices.               |
| SMB (Samba)   | Protocol: SMB. Function: Samba provides file and printer sharing capabilities for Windows clients on a Unix-like system. Security: Secure with proper configuration, access controls, and adherence to security best practices. |
| Yppasswdd     | Protocol: N/A. Function: Yppasswdd is the YP (Yellow Pages) password update daemon. Security: Secure with proper configuration and access controls; limit access to authorized systems.        |
| Ypserv        | Protocol: N/A. Function: Ypserv is the YP (NIS) server responsible for serving Yellow Pages information. Security: Secure with proper configuration and access controls; limit access to authorized systems.                    |
| Ypxfrd        | Protocol: N/A. Function: Ypxfrd is the YP (NIS) transfer daemon responsible for transferring NIS maps between servers. Security: Secure with proper configuration and access controls; limit access to authorized systems.             |

</details>

```sh
# Telnet
sudo systemctl stop telnet & sudo apt remove --purge --auto-remove -y telnet
# rlogin
sudo systemctl stop rlogin & sudo apt remove --purge --auto-remove -y rlogin
# rexec
sudo systemctl stop rexec & sudo apt remove --purge --auto-remove -y rexec
# rsh
sudo systemctl stop rsh & sudo apt remove --purge --auto-remove -y rsh
# vsftpd
sudo systemctl stop vsftpd & sudo apt remove --purge --auto-remove -y vsftpd
# finger
sudo systemctl stop finger & sudo apt remove --purge --auto-remove -y finger
# authd
sudo systemctl stop authd & sudo apt remove --purge --auto-remove -y authd
# netdump
sudo systemctl stop netdump & sudo apt remove --purge --auto-remove -y netdump
# netdump-server
sudo systemctl stop netdump-server & sudo apt remove --purge --auto-remove -y netdump-server
# nfs
sudo systemctl stop nfs & sudo apt remove --purge --auto-remove -y nfs
# rwhod
sudo systemctl stop rwhod & sudo apt remove --purge --auto-remove -y rwhod
# sendmail
sudo systemctl stop sendmail & sudo apt remove --purge --auto-remove -y sendmail
# smb (Samba)
sudo systemctl stop smb & sudo apt remove --purge --auto-remove -y smb
# yppasswdd
sudo systemctl stop yppasswdd & sudo apt remove --purge --auto-remove -y yppasswdd
# ypserv
sudo systemctl stop ypserv & sudo apt remove --purge --auto-remove -y ypserv
# ypxfrd
sudo systemctl stop ypxfrd & sudo apt remove --purge --auto-remove -y ypxfrd
```

Functions: 
Disable IPv6 Router Advertisements:
Command:

```sh
# Disable IPv6 Router Advertisements
sudo sysctl -w net.ipv6.conf.all.accept_ra=0
# Disable IPv6 Autoconfiguration
sudo sysctl -w net.ipv6.conf.all.autoconf=0

# Disable Network Packet Forwarding
sudo sysctl -w net.ipv4.ip_forward=0
# Disable Network File System (NFS)
sudo systemctl disable nfs-server.service
sudo systemctl disable nfs-client.target
```


### SSH client/server hardening

1. Install OpenSSH client/server
2. Configure and harden OpenSSH client/server
   - Disable root login
   - Disable password authentication
   - Enable SSH key authentication
   - Use strong cipher (AES-256-CBC, HMAC-SHA256)
   - Enable logging
   - Disable empty passwords
3. Firewall config for OpenSSH in iptables
   - Drop all SSH connection attempts from the IP address [IP address] that fail to complete within 10 retries.
   - Drop all SSH connection attempts from the MAC address [MAC address] that fail to complete within 10 retries
4. Generate and authenticate authorization keys
   - rsa 4096 bit
5. Launch OpenSSH on boot

```sh
### 1. Install OpenSSH server & client
sudo apt install openssh-server

### 2. Configure OpenSSH and harden it
####### CLIENT #######
# Disable root login
echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/ssh_config
# Disable password authentication
echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/ssh_config
# Enable SSH key authentication
echo 'PubkeyAuthentication yes' | sudo tee -a /etc/ssh/ssh_config
# Use strong ciphers
echo 'Ciphers AES-256-CBC' | sudo tee -a /etc/ssh/ssh_config
echo 'Macs HMAC-SHA256' | sudo tee -a /etc/ssh/ssh_config
# Enable logging
echo 'SyslogFacility AUTH' | sudo tee -a /etc/ssh/ssh_config
echo 'LogLevel INFO' | sudo tee -a /etc/ssh/ssh_config
# Disable empty passwords
echo 'PermitEmptyPasswords no' | sudo tee -a /etc/ssh/ssh_config

####### SERVER #######
# Disable root login
echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config
# Disable password authentication
echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config
# Enable SSH key authentication
echo 'PubkeyAuthentication yes' | sudo tee -a /etc/ssh/sshd_config
# Use strong ciphers
echo 'Ciphers AES-256-CBC' | sudo tee -a /etc/ssh/sshd_config
echo 'Macs HMAC-SHA256' | sudo tee -a /etc/ssh/sshd_config
# Enable logging
echo 'SyslogFacility AUTH' | sudo tee -a /etc/ssh/sshd_config
echo 'LogLevel INFO' | sudo tee -a /etc/ssh/sshd_config
# Disable empty passwords
echo 'PermitEmptyPasswords no' | sudo tee -a /etc/ssh/sshd_config

### 3. Firewall config for OpenSSH in iptables
# Drop all SSH connection attempts from the IP address [IP address] that fail to complete within 10 retries. 
iptables -A INPUT -p tcp -s [IP address] -j REJECT --syn --max-retries 10
# Drop all SSH connection attempts from the MAC address [MAC address] that fail to complete within 10 retries
iptables -A INPUT -m mac --mac-source [MAC address] -p tcp -j REJECT --syn --max-retries 10

### 4. Generate and authenticate authorization keys 
# Generate keys to authenticate (MY_KEY) | -f is name of keys
# This will result in generating two keys: public and private. You will be prompted to give it name for example (MY_KEY), and asked to use password (used during loging via ssh). ALWAYS KEEP THE PRIVATE KEY SAFE.
ssh-keygen -t rsa -b 4096 -f (MY_KEY)
# Authorize key
cd ~/.ssh
touch ~/.ssh/authorized_keys
# Place remote user's public key into authorization
cat ~/.ssh/(MY_KEY).pub >> ~/.ssh/authorized_keys
ssh-copy-id (MY_REMOTE_USER)@(MY_IP)

### 5. Launch OpenSSH on boot
sudo systemctl enable openssh-server

# Restart OpenSSH
sudo systemctl restart openssh-server
```


---


# 📛 Firewall & Security


### Iptables

Iptables is a user-space utility that allows a system administrator to configure the IP packet filter rules of the Linux kernel firewall, implemented by different Netfilter modules. It offers a flexible and powerful interface for managing network traffic rules, enabling the creation of sophisticated firewall policies.

1. Use secure network protocols and disable insecure ones.
1. Block protocols
- ICMP, 
```sh
# - ICMP (Internet Control Message Protocol) - Drop all incoming packets from all IP's.
sudo iptables -A INPUT -p icmp -j DROP
```
2. Block traffic on specific ports
- 22, 443, 53, implicit deny
- Optional: 80
```sh
# Flush existing rules
sudo iptables -F

# Allow specific ports: SSH, DNS, HTTPS
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT

# Drop all other incoming traffic
sudo iptables -A INPUT -j DROP

# Allow specific ports for outgoing traffic: SSH, DNS, HTTPS
sudo iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

### Firewall evasion block
# Drop invalid packets
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
# Fragmented packets
sudo iptables -A INPUT -f -j DROP
# XMAS packets (all flags set)
sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
# Null packets (no flags set)
sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
# SYN-FIN combination packets
sudo iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
# SYN-RST combination packets
sudo iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
# FIN-PSH-URG combination packets
sudo iptables -A INPUT -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j DROP

# Drop all traffic on specific ports associated with malware
sudo iptables -A INPUT -p all --match multiport --sports 23432,31338,31337,31339,18006,139,12349,44444,6667,8012,80,7597,21,4000,3150,666,2140,1026,10048,64666,23,22222,6969,11000,7626,113,10100,1001,21544,3131,7777,1243,6267,25,6776,25685,27374,68,6400,1120,12345,7300,1234 -j DROP

# Drop malicious IP's
# https://www.projecthoneypot.org/
# https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/027/943/original/ip_filter.blf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAU7AK5ITMJQBJPARJ%2F20231225%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20231225T212013Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=a38647e23b9d760e8bdef781c99d6c78760b2856b9ada38ff76d619807046045

# Drop all other outgoing traffic
sudo iptables -A OUTPUT -j DROP
```


---


### Fail2Ban

Fail2Ban scans log files like /var/log/auth.log and bans IP addresses conducting too many failed login attempts. It does this by updating system firewall rules to reject new connections from those IP addresses, for a configurable amount of time.

- Install requirements & software
- Configure service
- Adjust logging and "ban" rate requirements


```sh
### Install requirements
# Install Python (version 3.5 or later)
sudo apt install python3 -y
# Install pip (Python package installer)
sudo apt install python3-pip -y
# Install setuptools and distutils
sudo apt install python3-setuptools python3-distutils -y
# Install PyPy3
sudo apt install pypy3 -y

### Install fail2ban
# Install fail2ban
apt-get install fail2ban
#

here
```

How to use fail2ban
Main syntax:
```sh
fail2ban-client -h
```


---


### ✔️ Prerequisites

Before you begin, ensure that you have the following prerequisites installed:

>  ` Linux`


### 🎮 Using SLH

1. Run terminal on choosen machine.
2. Update your system - optionally upgrade distribution
3. Choose section of hardening scripts and execute them with elevated privileges.

### Legend of objects in scripts
1. Accounts and system
```sh
Root (MY_SUDO_USER):
    root:root
Regular user:
    danny:password
Remote user using SSH (MY_REMOTE_USER)
    danny:danny
System IP
    (MY_IP)
```
```sh
2. Values to change by user
Hash value for sudo user password:
    MY_SUDO_HASH
Public key:
    MY_PUBLIC_KEY
Private key:
    MY_PRIVATE_KEY
```


---


### ⚠️ Warning

While developing SLH (Secure Linux Hardening) scripts, I encountered instances where improper modifications led to system failures or **full bricking**. Deploying these scripts in a production environment without thorough testing can result in irreversible damage to critical system functions. Working on **snapshots** is highly recommended in this manner.

Key Points:

1. Testing is Crucial: Prioritize testing SLH scripts in a dedicated environment to avoid unpredictable consequences.
2. Production Caution: Refrain from deploying scripts directly in production without rigorous testing due to the potential for unforeseen issues.
3. Understand the scripts: Exercise caution, understand the impact of changes, and follow best practices for system configuration and security.
4. Documentation and Backup: Document changes, maintain backups, and monitor system modifications for security and reliability.
5. Stay Informed: Keep updated on script improvements, security practices, and Linux administration for a secure environment.
6. Adopt Gradually: If deploying in production, adopt changes gradually, monitoring closely for unexpected issues.
7. Customization Matters: Customize scripts based on specific environment needs to balance security and functionality.

**Use SLH wisely to enhance security while minimizing risks.**


---


## 🗺 Roadmap

> - [X] ` Task 1: Establish firewall rules (implicit deny)`

> - [ ] ` Incoming feature 1: Kernel isolation features`
> - [ ] ` Incoming feature 2: More automatisation - one shell script to harden Linux`
> - [ ] ` Incoming feature 3: Add banner on password prompt`

---


## 🤝 Contributing

Contributions are always welcome! Please follow these steps:
1. Fork the project repository. This creates a copy of the project on your account that you can modify without affecting the original project.
2. Clone the forked repository to your local machine using a Git client like Git or GitHub Desktop.
3. Create a new branch with a descriptive name (e.g., `NEW_FIX`).
```sh
git checkout -b NEW_FIX
```
4. Make changes to the project's codebase.
5. Commit your changes to your local branch with a clear commit message that explains the changes you've made.
```sh
git commit -m 'Applied changes.'
```
6. Push your changes to your forked repository on GitHub using the following command
```sh
git push origin NEW_FIX
```
7. Create a new pull request to the original project repository. In the pull request, describe the changes you've made and why they're necessary.
The project maintainers will review your changes and provide feedback or merge them into the main branch.


---


## 📄 License

Non-Commercial Use ONLY.


---


## 👏 Acknowledgments

  `ℹ️  National Institute of Standards and Technology`
  
  `ℹ️  Center for Internet Security`

  `ℹ️  Stack Overflow`

  `ℹ️  Red Hat`
   
  `ℹ️  ChatGPT 4.0`
   
  `ℹ️  Readme-ai https://github.com/eli64s/readme-ai`

  `ℹ️  Logo.com https://logo.com`

  
---


## 🗃️ Changelog


SLH v.1.0 is currently first and most up-to-date version, no previous versions were stated.

