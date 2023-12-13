# Scripted Linux Hardening (SLH) v.1.0

## System Maintenance
Update system and services
```sh
sudo apt dist-upgrade & sudo apt update & sudo apt upgrade
```
Removal of unnecessary libraries
```sh
sudo apt-get autoremove & sudo apt-get autoremove --purge
```
## Services



## User privileges
Password policies:
```sh
#!/bin/bash
# Set the maximum password age to 30 days
sudo echo "password [success=1 default=ignore]       pam_unix.so maxage=30" >> /etc/pam.d/sshd
# Add password complexity requirements
sudo echo "password [success=1 default=ignore]       pam_unix.so minlen=12 minclasstype=4 minlenclasses=4" >> /etc/pam.d/sshd
# Reload the PAM configuration
sudo pam-auth-update
# Restart the service
sudo systemctl restart sshd
```
## Kernel


## File System:
> Implement proper file system permissions.
> Utilize file system encryption for sensitive data.

## Network Configuration:
Configure and maintain firewall rules using tools like iptables.
Disable unnecessary network services and ports.
Use secure network protocols and disable insecure ones.

## Logging and Auditing:

## Configure and monitor system logs for security events.
Implement centralized logging for better analysis.

## Authentication:
Enforce strong password policies.
Implement multi-factor authentication where possible.
