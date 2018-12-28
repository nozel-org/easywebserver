# EasyWebserver
You want a reasonably secure webserver based on Debian? Well, you are in luck! This shell script does exactly that.

## Reason
Too many webservers are not secured adequately. I hope that this script will enable newbies to better secure their webserver. There are a lot of comments in the script so it is easier to follow for the less experienced.

## How to use
1. Become root (`su root`)
2. Download `easywebserver.sh` (use `git`, `wget`, `curl` etc.)
3. Execute `easywebserver.sh` (`bash easywebserver.sh` or `chmod +x easywebserver.sh && ./easywebserver.sh`)

## What does it do?
Quite a lot actually! It transforms a clean installation of a supported operating system in a fully functional webserver that has been secured reasonably well. When finished, you should be able to host your favorite CMS (e.g. Wordpress, Drupal etc.). The most important things it does are:

* Basic software (most of it is optional).
* Creates a user account with correctly set sudo privileges, ssh configuration and folder permissions.
* Creates a backup account with automated daily backups.
* Installs and configures a basic firewall.
* Hardens the (web)server, SSH, SSL/TLS and MySQL.
* Configure automatic security updates.

## Software
You might wonder what software will be installed. Below is a short list, check the wiki for the long list. Please note that most software is optional, these preferences can be changed in the `USER VARIABLES` section at the top of the script.

* The Apache webserver
* PHP + some extentions
* MariaDB
* Let's Encrypt / Certbot
* Uncomplicated Firewall (UFW)
* Some commonly used software

## Requirements
* A clean install of one of the followwing operating systems:
    * Debian 8 Jessie
    * Debian 9 Stretch
    * CentOS 7
    * Fedora 27
    * Fedora 28
    * Fedora 29
* Run the script as root
* Have a working internet connection with DNS
* Some free disk space

## Plans and ideas for 2019
* CentOS 8 support
* Fedora 30 support
* FreeBSD 12 support
* HardenedBSD 12 support
* Debian 10 support
* Choice between apache and nginx?
* Variable project url for importing your own resources
