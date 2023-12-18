# Scripted Linux Hardening (SLH) v.1.0

<p align="center">
  <img src="https://img.shields.io/badge/Linux-blue?style=for-the-badge&logo=Linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Bash-gold?style=for-the-badge&logo=Bash&logoColor=red" />
  <img src="https://img.shields.io/badge/NIST-orange?style=for-the-badge&logo=nist&logoColor=white" />
  <img src="https://img.shields.io/badge/CIS-purple?style=for-the-badge&logo=cis&logoColor=white" />
  <img src="https://img.shields.io/badge/OSHardening-black?style=for-the-badge" />
</p>

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
# - Services to stop:
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






<details closed><summary>Services</summary>

| Service                                                                   | Details                                                                                                                                                                                                            |
| ---                                                                    | ---                                                                                                                                                                                                                |
| Windows Defender | Protocol: N/A. Function: Antivirus and antimalware tool. Use: System protection. Security: Reliable; ensure regular updates for best protection. |
| Windows Firewall | Protocol: N/A. Function: Filters incoming/outgoing network traffic. Use: Network security. Security: Essential for system protection; configure rules appropriately. |


</details>

<details closed><summary>Features</summary>
- telnet, rlogin, rsh, vsftpd, finger, authd, netdump, netdump-server, nfs, rwhod, sendmail, smb (Samba), yppasswdd, ypserv, ypxfrd


# - Use secure network protocols and disable insecure ones.
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
