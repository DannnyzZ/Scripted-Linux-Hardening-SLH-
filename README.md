# Scripted Linux Hardening (SLH) v.1.0
# Scripted Linux Hardening (SLH) v.1.0

# ___________________| System Maintenance |_____________________________________________ #
# 1. System updates
#       - Update system and services
#       - Update distribution
#       - Set automatic updates every one week

# Update distribution (might cause problem with used apt process)
sudo apt dist-upgrade
# Update system and services
sudo apt update & sudo apt upgrade

# 2. Libraries
#       - Remove unnecessary libraries

# Removal of unnecessary libraries
sudo apt-get autoremove & sudo apt-get autoremove --purge


# ___________________| Accounts |________________________________________________________#
# 1. Password policies
# - Password age
# - Password complexity requirements
# - Implement multi-factor authentication where possible.


#!/bin/bash
# Set the maximum password age to 30 days
sudo echo "password [success=1 default=ignore]       pam_unix.so maxage=30" >> /etc/pam.d/sshd
# Add password complexity requirements
sudo echo "password [success=1 default=ignore]       pam_unix.so minlen=12 minclasstype=4 minlenclasses=4" >> /etc/pam.d/sshd
# Reload the PAM configuration
sudo pam-auth-update
# Restart the service
sudo systemctl restart sshd

# 2.
# 3.

# ___________________| Kernel |__________________________________________________________#


# ___________________| File System |_____________________________________________________#
# - Implement proper file system permissions.
# - Utilize file system encryption for sensitive data.


# ___________________| Firewall |_________________________________________________________#
# - Configure and maintain firewall rules using tools like iptables.


# ___________________| Logging and auditing |_____________________________________________#
# - Implement centralized logging for better analysis.


# ___________________| Network and Services |_________________________________________ ____#
# - Disable unnecessary network services and ports.
# - Use secure network protocols and disable insecure ones.
## Configure and monitor system logs for security events.
Implement centralized logging for better analysis.

## Authentication:
Enforce strong password policies.
Implement multi-factor authentication where possible.
