# Scripted Linux Hardening (SLH) v.1.0 UNDER DEVELOPMENT

<p align="center">
  <img src="https://img.shields.io/badge/Linux-blue?style=for-the-badge&logo=Linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Bash-gold?style=for-the-badge&logo=Bash&logoColor=red" />
  <img src="https://img.shields.io/badge/NIST-orange?style=for-the-badge&logo=nist&logoColor=white" />
  <img src="https://img.shields.io/badge/CIS-purple?style=for-the-badge&logo=cis&logoColor=white" />
  <img src="https://img.shields.io/badge/OSHardening-black?style=for-the-badge" />
</p>

About SLH - WRITE HERE
Guidelines: 
> Red Hat: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/security_guide/index
> CIS
> NIST

---


## 📒 Table of Contents
- [📒 Table of Contents](#-table-of-contents)
- [📍 Overview](#-overview)
- [🚀 Getting Started](#-getting-started)
  - [✔️ Prerequisites](#️-prerequisites)
  - [⚠️ Warning](#-Warning)
- [🗺 Roadmap](#-roadmap)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [👏 Acknowledgments](#-acknowledgments)
- [🗃️ Changelog](#-changelog)


---


# 🛠️ SYSTEM MAINTENANCE
1. Update distribution
2. Update system and services
3. Remove unnecessary libraries
4. Set automatic updates every one week

```sh
# Update distribution (might cause problem with used apt process)
sudo apt dist-upgrade
# Update system and services
sudo apt update & sudo apt upgrade
# Removal of unnecessary libraries
sudo apt-get autoremove & sudo apt-get autoremove --purge
```


# 👨‍💼 ACCOUNTS
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


# 🔳 KERNEL


# 🗃️ FILE SYSTEM
1. Implement proper file system permissions.
2. Utilize file system encryption for sensitive data.


# 🧾 LOGGING AND AUDITING
1. Implement centralized logging for better analysis.


# 📛 NETWORK, SERVICES, FIREWALL
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

### Main syntax
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

# Drop all other outgoing traffic
sudo iptables -A OUTPUT -j DROP
```


---


### ✔️ Prerequisites

Before you begin, ensure that you have the following prerequisites installed:

>  ` Linux`

### 🎮 Using SLH

1. Run terminal on choosen machine.
2. Execute commands.


---


### ⚠️ Warning

**Using SLH Safely:**

WRITE HERE

**Use SLH wisely to enhance security while minimizing risks.**


---


## 🗺 Roadmap

> - [X] ` Task 1: Establish firewall rules based on "implicit deny" rule`
> - [X] ` Task 2: `
> - [X] ` Task 3: `

> - [ ] ` Incoming feature 1: Kernel isolation`
> - [ ] ` Incoming feature 2: `
> - [ ] ` Incoming feature 3: `


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

WRITE HERE


---

