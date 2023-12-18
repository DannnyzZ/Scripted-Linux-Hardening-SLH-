# Scripted Linux Hardening (SLH) v.1.0

# System Maintenance
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

# 2. Libraries

# Accounts
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

# Kernel


# File System
1. Implement proper file system permissions.
2. Utilize file system encryption for sensitive data.


# Firewall
1. Configure and maintain firewall rules using tools like iptables.


# Logging and auditing
1. Implement centralized logging for better analysis.


# Network and Services
1. Disable and/or uninstall unnecessary network services.
# - Check status of service
systemctl status <service_name>
systemctl show --property=ActiveState --property=SubState <service_name>
# - Get info about package
systemctl list-unit-files | grep <package_name>
# - Stop, disable, uninstall service, remove its package.
sudo systemctl stop <service_name> && sudo apt remove --purge --auto-remove -y <package_name>
# - Services to stop:

telnet
rlogin
rsh
vsftpd
finger
authd
netdump
netdump-server
nfs
rwhod
sendmail
smb (Samba)
yppasswdd
ypserv
ypxfrd
telnet



# - Use secure network protocols and disable insecure ones.
```sh
# - ICMP (Internet Control Message Protocol) - Drop all incoming packets from all IP's.
sudo iptables -A INPUT -p icmp -j DROP
# Allow specific ports: SSH, DNS, HTTP, HTTPS
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT

# Drop all other incoming traffic
sudo iptables -A INPUT -j DROP

# Allow specific ports for outgoing traffic: SSH, DNS, HTTP, HTTPS
sudo iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

# Drop all other outgoing traffic
sudo iptables -A OUTPUT -j DROP
```
