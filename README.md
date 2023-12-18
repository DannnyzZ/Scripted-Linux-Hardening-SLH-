# Scripted Linux Hardening (SLH) v.1.0

<p align="center">
  <img src="https://img.shields.io/badge/Linux-blue?style=for-the-badge&logo=Linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Bash-gold?style=for-the-badge&logo=Bash&logoColor=red" />
  <img src="https://img.shields.io/badge/NIST-orange?style=for-the-badge&logo=nist&logoColor=white" />
  <img src="https://img.shields.io/badge/CIS-purple?style=for-the-badge&logo=cis&logoColor=white" />
  <img src="https://img.shields.io/badge/OSHardening-black?style=for-the-badge" />
</p>

---

About SLH - WRITE HERE

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


### Main syntax
```sh
# Set the maximum password age to 30 days
sudo echo "password [success=1 default=ignore]       pam_unix.so maxage=30" >> /etc/pam.d/sshd
# Add password complexity requirements
sudo echo "password [success=1 default=ignore]       pam_unix.so minlen=12 minclasstype=4 minlenclasses=4" >> /etc/pam.d/sshd
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

1. telnet, rlogin, rsh, vsftpd, finger, authd, netdump, netdump-server, nfs, rwhod, sendmail, smb (Samba), yppasswdd, ypserv, ypxfrd

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

**Using OSFortify Safely:**

WRITE HERE

**Use SLH wisely to enhance security while minimizing risks.**

---

## 🗺 Roadmap

> - [X] ` Task 1: `

> - [ ] ` Incoming feature 1: `

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
