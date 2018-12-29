#!/bin/bash

#############################################################################
# Version 0.1.4-ALPHA (29-12-2018)
#############################################################################

#############################################################################
# Copyright 2016-2018 Nozel/Sebas Veeke. Licenced under a Creative Commons 
# Attribution-NonCommercial-ShareAlike 4.0 International License.
#
# See https://creativecommons.org/licenses/by-nc-sa/4.0/
#
# Contact:
# > e-mail      mail@nozel.org
# > GitHub      onnozel
#############################################################################

#############################################################################
# USER VARIABLES
#############################################################################

# Install and configure additional software
INSTALL_MYSQL='yes' # either 'yes' or 'no'
INSTALL_PHP='yes' # either 'yes' or 'no'
INSTALL_CERTBOT="yes" # either 'yes' or 'no'

# configure basic firewall with UFW (recommended)
FIREWALL='yes' # either 'yes' or 'no'

# automatic daily backup
AUTOMATIC_BACKUP='yes' # either 'yes' or 'no'
BACKUP_USER='robot' # 'backup' is not possible since that is a system user

# automatic security update (recommended)
AUTOMATIC_SECURITY_UPDATES='yes' # either 'yes' or 'no'

# remove cockpit. when you are not sure what to do, leave it on 'yes' (Fedora only)
REMOVE_COCKPIT='yes' # either 'yes' or 'no'

#############################################################################
# SCRIPT VARIABLES
#############################################################################

SCRIPT_VERSION='0.1.4'

#set -e # stop the script on errors
#set -u # unset variables are an error
#set -o pipefail # piping a failed process into a successful one is an arror

#############################################################################
# LICENSE AND INTRODUCTION
#############################################################################

clear
echo
echo "#############################################################################"
echo "# Copyright 2016-2018 Nozel/Sebas Veeke. Licenced under a Creative Commons  #" 
echo "# Attribution-NonCommercial-ShareAlike 4.0 International License.           #"
echo "#                                                                           #"
echo "# See https://creativecommons.org/licenses/by-nc-sa/4.0/                    #"
echo "#                                                                           #"
echo "# Contact:                                                                  #"
echo "# > e-mail      mail@nozel.org                                              #"
echo "# > GitHub      onnozel                                                     #"
echo "#############################################################################"
echo
echo "This script will install and configure a fully functioning reasonably secure"
echo "webserver."
echo
echo "Press ctrl + c during the script to abort."

sleep 2

#############################################################################
# CHECKING REQUIREMENTS
#############################################################################

echo
echo
echo "REQUIREMENTS CHECK"

# checking whether the script runs as root
echo -n "[?] Script is running as root..."
if [ "$EUID" -ne 0 ]; then
    echo -e "\\t\\t\\t\\t[NO]"
    echo
	echo "[!] Error: this script should run with root privileges. Please try again with su root or sudo."
    echo
	exit 1
else
    echo -e "\\t\\t\\t\\t[yes]"
fi

# checking whether script user variables are valid
echo -n "[?] Script user variables are valid..."
if [ "${INSTALL_MYSQL}" == "yes" ] || [ "${INSTALL_MYSQL}" == "no" ] && \
[ "${INSTALL_PHP}" == "yes" ] || [ "${INSTALL_PHP}" == "no" ] && \
[ "${INSTALL_CERTBOT}" == "yes" ] || [ "${INSTALL_CERTBOT}" == "no" ] && \
[ "${AUTOMATIC_BACKUP}" == "yes" ] || [ "${AUTOMATIC_BACKUP}" = "no"] && \
[ "${AUTOMATIC_SECURITY_UPDATES}" == "yes" ] || [ "${AUTOMATIC_SECURITY_UPDATES}" == "no" ] && \
[ "${BACKUP_USER}" != "backup" ] && \
[ "${REMOVE_COCKPIT}" == "yes" ] || [ "${REMOVE_COCKPIT}" == "no" ]; then
    echo -e "\\t\\t[YES]"
else
    echo -e "\\t\\t[NO]"
    echo
    echo "[!] Error: the script's user variables aren't valid."
    echo
    exit 1
fi

# checking whether supported operating system is installed
echo -n "[?] OS is supported..."
# source /etc/os-release to use variables
if [ -f /etc/os-release ]; then
    . /etc/os-release

    # put distro name and version in variables
    OS_NAME="$NAME"
    OS_VERSION="$VERSION_ID"

    # check all supported combinations of OS and version
    if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 7" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 8" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 27" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 28" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 29" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 30" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 8" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 9" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 10" ]; then
        echo -e "\\t\\t\\t\\t\\t\\t[YES]"
    else
        echo -e "\\t\\t\\t\\t\\t\\t[NO]"
        echo
        echo "[!] Error: this operating system is not supported. Supported operating systems:"
        echo
        echo "- CentOS 7, 8"
        echo "- Fedora 27, 28, 29, 30"
        echo "- Debian 8, 9, 10"
        echo
        echo "Or request support by creating an issue on GitHub."
        echo
        exit 1
    fi

else
    echo -e "\\t\\t\\t\\t\\t\\t[NO]"
    echo
    echo "[!] Error: this operating system is not supported. Supported operating systems:"
    echo
    echo "- CentOS 7, 8"
    echo "- Fedora 27, 28, 29, 30"
    echo "- Debian 8, 9, 10"
    echo
    echo "Or request support by creating an issue on GitHub."
    echo
    exit 1
fi

# checking internet connection
echo -n "[?] Connected to the internet..."
if ping -q -c 1 -W 1 google.com >/dev/null; then
    echo -e "\\t\\t\\t\\t[YES]"

else
    echo -e "\\t\\t\\t\\t[NO]"
    echo
    echo "[!] Error: access to the internet is required."
    echo
    exit 1
fi

#############################################################################
# USER INPUT AND CONFIGURATION
#############################################################################

echo
echo
echo "USER INPUT"
echo "[i] The script will gather some information from you."

# choose hostname
echo
read -r -p "[?] Enter server's hostname:                            " HOSTNAME

# choose password backup account
while true
    do
        read -r -s -p "[?] Enter backup account password:                      " BACKUP_PASSWORD1
        echo
        read -r -s -p "[?] Enter backup account Password (again):              " BACKUP_PASSWORD2
            [ "${BACKUP_PASSWORD1}" = "${BACKUP_PASSWORD2}" ] && break
            echo
            echo "[!] Error: your passwords don´t match, please try again."
            echo
        echo
    done

# check whether the user wants to create a user account
echo
while true
    do
        read -r -p "[?] Add a user account? (yes/no):                       " ADD_USER
            [ "${ADD_USER}" = "yes" ] || [ "${ADD_USER}" = "no" ] && break
            echo
            echo "[!] Error: please type yes or no and press enter to continue."
            echo
    done

# choose username user account
if [ "$ADD_USER" = "yes" ]; then
    read -r -p "[?] Enter account username:                             " USERNAME

    ## choose password user account
    while true
        do
            read -r -s -p "[?] Enter user account password:                        " USER_PASSWORD1
            echo
            read -r -s -p "[?] Enter user account Password (again):                " USER_PASSWORD2
                [ "${USER_PASSWORD1}" = "${USER_PASSWORD2}" ] && break
                echo
                echo "[!] Error: your passwords don´t match, please try again."
                echo
        done

    # add content of AuthorizedKeysFile
    echo
    read -r -p "[?] Enter AuthorizedKeysFile's content:                 " SSH
fi

# choose MariaDB/MySQL root password
if [ "${INSTALL_MYSQL}" = "yes" ]; then
    while true
        do
        read -r -s -p "[?] Enter MariaDB/MySQL root password:                  " MYSQL_PASSWORD1
            echo
            read -r -s -p "[?] Enter MariaDB/MYSQL root Password (again):          " MYSQL_PASSWORD2
                [ "${MYSQL_PASSWORD1}" = "${MYSQL_PASSWORD2}" ] && break
                echo
                echo "[!] Error: your passwords don´t match, please try again."
                echo
        done

#############################################################################
# SYSTEM CHANGES
#############################################################################

echo
echo
echo "SYSTEM CHANGES"

# change hostname to provided hostname
echo "[+] Modifying /etc/hostname..."
echo "${HOSTNAME}" > /etc/hostname

# update repositories for Debian and Ubuntu
if [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 8" ]; then
    echo "[+] Modifying sources.list..."
    wget -q https://raw.githubusercontent.com/onnozel/easywebserver/master/resources/debian8-sources.list -O /etc/apt/sources.list --no-check-certificate
elif [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 9" ]; then
    echo "[+] Modifying sources.list..."
    wget -q https://raw.githubusercontent.com/onnozel/easywebserver/master/resources/debian9-sources.list -O /etc/apt/sources.list --no-check-certificate
elif [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 10" ]; then
    echo "[+] Modifying sources.list..."
    wget -q https://raw.githubusercontent.com/onnozel/easywebserver/master/resources/debian10-sources.list -O /etc/apt/sources.list --no-check-certificate
fi

# remove cockpit from Fedora since it's extra attack surface normal users don't need
if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 8" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 27" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 28" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 29" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 30" ]; then
    echo "[+] Stopping cockpit..."
    systemctl stop cockpit
    systemctl disable cockpit
    echo "[+] Removing cockpit..."
    dnf -y -q remove cockpit cockpit-dashboard
fi

#############################################################################
# UPDATE OPERATING SYSTEM
#############################################################################

echo
echo
echo "UPDATE OPERATING SYSTEM"
# update CentOS 7
if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 7" ]; then
    echo "[+] Downloading packages from repositories and upgrade..."
    yum -y -q update
fi

# update CentOS 8+ and Fedora
if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 8" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 27" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 28" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 29" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 30" ]; then
    echo "[+] Downloading packages from repositories and upgrade..."
    dnf -y -q update
fi

# update Debian
if [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 8" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 9" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 10" ]; then
    echo "[+] Downloading package list from repositories..."
    apt-get -qq update

    echo "[+] Downloading and upgrading packages..."
    apt-get -y -qq upgrade
fi

#############################################################################
# INSTALL NEW SOFTWARE
#############################################################################

echo
echo
echo "INSTALL NEW SOFTWARE"

# install software on CentOS 7
if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 7" ]; then
    # this software will always be installed
    echo "[+] Installing basic software..."
    yum -y -q install httpd wget chrony zip unzip nano sudo

    if [ "${INSTALL_PHP}" == "yes" ]; then
        # default CentOS 7 repo has a very old php 5.4. remi repo is used 
        # for php 7.2 packages, which are supported until 20 november 2020
        echo "[+] Installing PHP..."
        yum -y -q install epel-release yum-utils
        yum -y -q install http://rpms.remirepo.net/enterprise/remi-release-7.rpm
        yum-config-manager --enable remi-php72
        yum -y -q update
        yum -y -q install php php-common php-cli php-json
    elif [ "${INSTALL_MYSQL}" == "yes" ]; then
        # default CentOS 7 repo has a very old MariaDB. official MariaDB repo
        # is used for MariaDB 10.3 stable, which is supported until may 2023
        echo "[+] Installing MySQL (MariaDB)..."
        wget https://raw.githubusercontent.com/onnozel/easywebserver/master/resources/centos7-mariadb.repo -O /etc/yum.repos.d/mariadb.repo
        yum -y -q update
        yum -y -q install mariadb-server php-pdo php-mysqlnd
    elif [ "${INSTALL_CERTBOT}" == "yes" ]; then
        # certbot is Let's Encrypt's tool for aquiring TLS certificates
        # in CentOS 7 it's part of the epel repository
        echo "[+] Installing certbot..."
        yum -y -q install epel-release
        yum -y -q install certbot python2-certbot-apache
    elif [ "${AUTOMATIC_SECURITY_UPDATES}" == "yes" ]; then
        # yum-cron is used for automatic security updates
        echo "[+] Installing automatic updates..."
        yum -y -q install yum-cron
    elif [ "${FIREWALL}" == "yes" ]; then
        echo "[+] Installing firewall tool..."
        yum -y -q remove firewalld
        yum -y -q install ufw
    fi
fi

# install software on CentOS 8+ and Fedora
if "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 8" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 27" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 28" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 29" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 30" ]; then
    # this software will always be installed
    echo "[+] Installing basic software..."
    dnf -y -q install httpd wget crony zip unzip nano sudo

    if [ "${INSTALL_PHP}" == "yes" ]; then
        # default repos are being used, since all php versions are 7.1+
        echo "[+] Installing PHP..."
        dnf -y -q install php php-common php-cli php-json
    elif [ "${INSTALL_MYSQL}" == "yes" ]; then
        # default repos are being used, since all MariaDB versions are 10.2+
        dnf -y -q install mariadb-server php-pdo php-mysqlnd
    elif [ "${INSTALL_CERTBOT}" == "yes" ]; then
        # certbot is Let's Encrypt's tool for aquiring TLS certificates
        # in CentOS 7 it's part of the epel repository
        echo "[+] Installing certbot..."
        dnf -y -q install epel-release
        dnf -y -q install certbot python2-certbot-apache
    elif [ "${AUTOMATIC_SECURITY_UPDATES}" == "yes" ]; then
        # dnf-automatic is used for automatic security updates
        echo "[+] Installing automatisch updates..."
        dnf -y -q install dnf-automatic
    elif [ "${FIREWALL}" == "yes" ]; then
        echo "[+] Installing firewall tool..."
        dnf -y -q remove firewalld
        dnf -y -q install ufw
    fi
fi

# Install software on Debian 8
if [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 8" ]; then
    # this software will always be installed
    echo "[+] Installing basic software..."
    apt-get -y -qq install apt-transport-https ca-certificates ntp sudo zip unzip curl apache2

    if [ "${INSTALL_PHP}" == "yes" ]; then
        # default repos are being used, some software will be old
        echo "[+] Installing PHP..."
        apt-get -y -qq install php5 php5-mysql php5-gd php5-curl libapache2-mod-php5
    elif [ "${INSTALL_MYSQL}" == "yes" ]; then
        # default repos are being used, some software will be old
        apt-get -y -qq install mariadb-server
    elif [ "${INSTALL_CERTBOT}" == "yes" ]; then
        # certbot is Let's Encrypt's tool for aquiring TLS certificates
        # in Debian 8 Let's Encrypt is part of backports
        echo "[+] Installing certbot..."
        apt-get -y -qq install python-certbot-apache python-certbot -t jessie-backports
    elif [ "${AUTOMATIC_SECURITY_UPDATES}" == "yes" ]; then
        # unattended-upgrades is used for automatic security updates
        echo "[+] Installing automatisch updates..."
        apt-get -y -qq install unattended-upgrades
    elif [ "${FIREWALL}" == "yes" ]; then
        echo "[+] Installing firewall tool..."
        apt-get -y -qq install ufw
    fi
fi

Install software on Debian 9 and 10
if [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 9" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 10" ]; then
    # this software will always be installed
    echo "[+] Installing basic software..."
    apt-get -y -qq install apt-transport-https ca-certificates ntp sudo zip unzip curl apache2

    if [ "${INSTALL_PHP}" == "yes" ]; then
        # default repos are being used, some software will be old
        echo "[+] Installing PHP..."
        apt-get -y -qq install php7.0 php7.0-mysql php7.0-gd php7.0-curl libapache2-mod-php7.0
    elif [ "${INSTALL_MYSQL}" == "yes" ]; then
        # default repos are being used, some software will be old
        apt-get -y -qq install mariadb-server
    elif [ "${INSTALL_CERTBOT}" == "yes" ]; then
        # certbot is Let's Encrypt's tool for aquiring TLS certificates
        # the default version is unfortunately old, but still somewhat usable
        echo "[+] Installing certbot..."
        apt-get -y -qq install python-certbot-apache python-certbot
    elif [ "${AUTOMATIC_SECURITY_UPDATES}" == "yes" ]; then
        # unattended-upgrades is used for automatic security updates
        echo "[+] Installing automatisch updates..."
        apt-get -y -qq install unattended-upgrades
    elif [ "${FIREWALL}" == "yes" ]; then
        echo "[+] Installing firewall tool..."
        apt-get -y -qq install ufw
    fi
fi

#############################################################################
# SETTING UP USER ACCOUNT
#############################################################################

if [ "${ADD_USER}" = "yes" ]; then
    echo
    echo
    echo "ADD USER ACCOUNT"

    # hashing the password for useradd
    echo "[+] Hashing password..."
    USER_HASH=$(openssl passwd -1 -salt temp "${USER_PASSWORD1}")

    # create the user account with chosen password and its own home directory
    echo "[+] Creating user account..."
    useradd "${USERNAME}" -s /bin/bash -m -U -p "${USER_HASH}"

    # create SSH folder
    echo "[+] Creating SSH folder..."
    mkdir /home/${USERNAME}/.ssh

    # add public key to AuthorizedKeysFile
    echo "[+] Adding public key..."
    echo "${SSH}" > /home/${USERNAME}/.ssh/authorized_keys

    # adding user to sudo
    echo "[+] Adding user account to sudo..."
    echo "${USERNAME}    ALL=(ALL:ALL) ALL" >> /etc/sudoers.d/${USERNAME}

    # setting folder and file permissions
    echo "[+] Setting folder and file permissions..."
    chown ${USERNAME}:${USERNAME} /home/${USERNAME}/.ssh
    chown ${USERNAME}:${USERNAME} /home/${USERNAME}/.ssh/authorized_keys
    chown root:root /etc/sudoers.d/${USERNAME}
    chmod 440 /etc/sudoers.d/${USERNAME}
    chmod 700 /home/${USERNAME}/.ssh
    chmod 600 /home/${USERNAME}/.ssh/authorized_keys
    chmod 440 /etc/sudoers.d/${USERNAME}
fi

#############################################################################
# SETTING UP BACKUP ACCOUNT
#############################################################################

if [ "${AUTOMATIC_BACKUP}" == "yes" ]; then
    echo
    echo
    echo "BACKUP USER"

    # hashing the password for useradd
    echo "[+] Hashing password..."
    BACKUP_HASH=$(openssl passwd -1 -salt temp "${BACKUP_PASSWORD1}")

    # create the backup user account with chosen password and its own home directory
    echo "[+] Creating user account..."
    useradd "${BACKUP_USER}" -s /bin/bash -m -U -p "${BACKUP_HASH}"

    # creating folders within the given backup account's home directory
    echo "[+] Creating backup folders..."
    mkdir /home/${BACKUP_USER}/backups
    mkdir /home/${BACKUP_USER}/scripts

    # adding handy scripts and readme to backup user folder
    # echo "[+] Adding scripts..."
    # wget -q # TO DO -O /home/${BACKUP_USER}/scripts/EasyDebianWebserver.sh
    # wget -q # TO DO -O /home/${BACKUP_USER}/scripts/add-user.sh
    # wget -q # TO DO -O /home/${BACKUP_USER}/readme.txt

    # setting folder and file permissions
    echo "[+] Setting folder and file permissions..."
    chown -R ${BACKUP_USER}:${BACKUP_USER} /home/${BACKUP_USER}/
    chmod -R 770 /home/${BACKUP_USER}/
fi

#############################################################################
# CONFIGURE FIREWALL
#############################################################################

if [ "${FIREWALL}" == "yes" ]; then
    echo
    echo
    echo "FIREWALL"

    if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 7" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 8" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 27" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 28" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 29" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 30" ]; then
        # deny incoming traffic by default
        echo "[+] Configuring firewall for incoming traffic..."
        ufw default deny incoming

        # allow ssh (22), http (80) and https (443) traffic through the firewall
        echo "[+] Configuring firewall for ssh, http and https traffic..."
        ufw limit ssh
        ufw allow http
        ufw allow https

        # make logging more usefull on UFW
        echo "[+] Activating logging..."
        ufw logging on

        # UFW isn't activated by default, this activates it
        echo "[+] Activating firewall on next boot..."
        sed -i s%'ENABLED=no'%'ENABLED=yes'%g /etc/ufw/ufw.conf
        chmod 0644 /etc/ufw/ufw.conf
    fi

    if [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 8" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 9" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 10" ]; then
        # Deny incoming traffic by default
        echo "[+] Configuring firewall for incoming traffic..."
        ufw default deny incoming

        # Allow ssh (22), http (80) and https (443) traffic through the firewall
        echo "[+] Configuring firewall for ssh, http and https traffic..."
        ufw limit ssh
        ufw allow http
        ufw allow https

        # Make logging more useful on UFW
        echo "[+] Activating logging..."
        ufw logging on

        # UFW isn't activated by default, this activates it on first reboot
        echo "[+] Activating firewall on next boot..."
        sed -i s%'ENABLED=no'%'ENABLED=yes'%g /etc/ufw/ufw.conf
        chmod 0644 /etc/ufw/ufw.conf
    fi
fi

#############################################################################
# CONFIGURE AUTOMATIC SECURITY UPDATES
#############################################################################

if [ "${AUTOMATIC_SECURITY_UPDATES}" == "yes" ]; then
    echo
    echo
    echo "AUTOMATIC UPDATES"

    if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 7" ];
        # change upgrade type from all available updates to only security updates
        echo "[+] Configuring automatic updates..."
        sed -i s%'update_cmd = default'%'update_cmd = security'%g /etc/yum/yum-cron.conf

        # make the server automatically apply the security updates
        sed -i s%'apply_updates = no'%'apply_updates = yes'%g /etc/yum/yum-cron.conf
        
        # enable the automatic updates
        echo "[+] Enabling automatic updates..."
        systemctl enable --now yum-cron
    fi

    if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 8" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 27" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 28" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 29" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Fedora 30" ]; then
        # change upgrade type from all available updates to only security updates
        echo "[+] Configuring automatic updates..."
        sed -i s%'upgrade_type = default'%'upgrade_type = security'%g /etc/dnf/automatic.conf

        # make the server automatically apply the security updates
        sed -i s%'apply_updates = no'%'apply_updates = yes'%g /etc/dnf/automatic.conf

        # enable the automatic install timer for dns-automatic
        echo "[+] Enabling automatic updates..."
        systemctl enable --now dnf-automatic-install.timer
    fi

    if [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 8" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 9" ] || \
    [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 10" ]; then
        # unattended-upgrades needs to be activated before it will work
        echo "[+] Activating unattended-upgrades..."
        echo "APT::Periodic::Update-Package-Lists \"1\";\\nAPT::Periodic::Unattended-Upgrade \"1\";\\n" > /etc/apt/apt.conf.d/20auto-upgrades
    fi
fi

#############################################################################
# CONFIGURE WEBSERVER AND CERTBOT
#############################################################################

echo
echo
echo "WEBSERVER"

if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 7" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 8" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 27" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 28" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 29" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 30" ]; then
    # the default ssl configuration needs to be hardened
    #echo "[+] Adding hardened ssl.conf..."
    #wget -q # TO DO > /etc/httpd/conf.d/ssl.conf

    if [ "${INSTALL_CERTBOT}" == "yes" ]; then
        # adding hardened ssl configuration
        #echo "[+] Adding hardenend TLS/SSL configuration..."
        #wget -q # TO DO -O /etc/letsencrypt/options-ssl-apache.conf
    fi

    # adding hardened configurations for http security headers
    #echo "[+] Adding http security headers..."
    #wget -q # TO DO -O /etc/httpd/conf.d/security.conf

    # Start apache and enable it on reboot
    echo "[+] Starting and enabling webserver..."
    systemctl enable --now httpd
fi

if [ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 8" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 9" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Debian GNU/Linux 10" ]; then
    echo "[+] Adding hardened ssl.conf..."
    #wget # TO DO -O /etc/apache2/mods-available/ssl.conf

    if [ "${INSTALL_CERTBOT}" == "yes" ]; then
        # adding hardened ssl configuration
        echo "[+] Adding hardened TLS/SSL configuration..."
        #wget -q # TO DO -O /etc/letsencrypt/options-ssl-apache.conf
    fi

    # adding hardened configurations for http security headers
    echo "[+] Adding http security headers..."
    wget -q # TO DO -O /etc/apache2/conf-available/security.conf

    # activate relevant apache2 modules and configurations
    echo "[+] Activating apache2 modules and configurations..."
    a2enmod rewrite
    a2enmod actions
    a2enmod ssl
    a2enmod headers
    a2enconf security.conf

    # restart webserver so changes can take effect
    echo "[+] Restarting webserver..."
    systemctl restart apache2
fi

#############################################################################
# CONFIGURE MYSQL
#############################################################################

if [ "${INSTALL_MYSQL}" = "yes" ]; then
    echo
    echo
    echo "MYSQL"

    echo "[+] Starting MariaDB..."
    systemctl start mariadb

    # harden MariaDB/MYSQL installation
    echo "[+] Adding password to MariaDB..."
    mysql -u root -e "UPDATE mysql.user SET Password=PASSWORD('${MYSQL_PASSWORD1}') WHERE User='root'"

    echo "[+] Disallow remote root login..."
    mysql -u root -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"

    echo "[+] Remove anonymous users..."
    mysql -u root -e "DELETE FROM mysql.user WHERE User=''"

    echo "[+] Remove test database and access to it..."
    mysql -u root -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%'"

    echo "[+] Flushing privileges..."
    mysql -u root -e "FLUSH PRIVILEGES"

    echo "[+] Restarting MariaDB..."
    systemctl enable --now mariadb
fi

#############################################################################
# CREATE AUTOMATIC BACKUP
#############################################################################

if [ "${AUTOMATIC_BACKUP}" == "yes" ]; then
    echo
    echo
    echo "AUTOMATIC BACKUP"

    # creating backup folders within the given backup account's home directory
    echo "[+] Creating backup folders..."
    mkdir -p /home/${BACKUP_USER}/backups/

    # adding backupscripts to folders
    echo "[+] Adding backup scripts..."
    #wget -q # TO DO -O /home/${BACKUP_USER}/scripts/backup-daily.sh
    #wget -q # TO DO -O /home/${BACKUP_USER}/scripts/backup-weekly.sh

    # replacing '$BACKUP_USER' in script with $BACKUP_USER variable value
    echo "[+] Customizing backup script..."
    #sed -i s%'$BACKUP_USER'%${BACKUP_USER}%g /home/${BACKUP_USER}/scripts/backup-daily.sh
    #sed -i s%'$BACKUP_USER'%${BACKUP_USER}%g /home/${BACKUP_USER}/scripts/backup-weekly.sh

    # setting folder and file permissions
    echo "[+] Setting folder and file permissions..."
    chown -R ${BACKUP_USER}:root /home/${BACKUP_USER}/backup
    chmod -R 770 /home/${BACKUP_USER}/backup

    # add cronjobs for backup scripts
    echo "[+] Adding cronjob for backup script..."
    echo -e "# This cronjob activates the backup_daily.sh script every day at 4:00.\n0 4 * * 1-6 root /home/${BACKUP_USER}/backup/backup-daily.sh\n\n# This cronjob activates the backup-weekly.sh script every week on sunday at 4:00.\n0 4 * * 0 root /home/${BACKUP_USER}/backup/backup-weekly.sh" > /etc/cron.d/automated-backup
fi

#############################################################################
# FINAL PREPERATION
#############################################################################

echo
echo
echo "FINAL PREPERATION"

# start and enable chronyd on CentOS and Fedora
if [ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 7" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "CentOS Linux 8" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 27" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 28" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 29" ] || \
[ "${OS_NAME} ${OS_VERSION}" == "Fedora 30" ]; then
    echo "[+] Start and enable chronyd..."
    systemctl enable --now chronyd
fi

#############################################################################
# FINAL NOTES
#############################################################################

echo
echo
echo
echo
echo "******************************************************************************************************"
echo "                                            IMPORTANT!                                                "
echo "******************************************************************************************************"
echo
echo "Although you now have a fully functional Debian based webserver, you still need to reboot"
echo "in order to make it more secure. Below is some additional information on your new server."
echo
echo
echo "  1.	README"
echo "  A README file and some scripts to help you on your way can be found in:"
echo
echo "      /home/${BACKUP_USER}/"
echo
echo "  2. 	FILE LOCATIONS"
echo "  Since a lot of different file locations are being used by all the modifications from this"
echo "  script, finding them can be quite cumbersome. Check the overview below for some help."
echo
echo "      README:                              /home/${BACKUP_USER}/"
echo "      Weekly and daily backup scripts:     /home/${BACKUP_USER}/scripts"
echo "      The archived backups:                /home/${BACKUP_USER}/backups"
echo "      Backup cronjobs:                     /etc/cron.d/automated-backup"
echo "      Sudo file from optional account:     /etc/sudoers.d/${USERNAME}"
echo
echo "  In the readme you can find more information on changing parameters, backup frequency or changing firewall rules."
echo
echo "  3. REBOOT SERVER!"
echo "  Last but certainly not least: you should reboot the server to enable the new hostname, firewall and"
echo "  pending kernel updates. Do this by running one of the following commands:"
echo
echo "      'shutdown -r now' or 'reboot'."
echo
echo
echo "    I hope you are happy with your new webserver and that it serves you (and others ;) well. If you"
echo "    have any questions you can post them on https://github.com/onnozel/easywebserver/issues."
echo
echo "******************************************************************************************************"
echo "                                            GOOD LUCK!"
echo "******************************************************************************************************"
echo
echo
exit 0
