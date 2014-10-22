#!/bin/sh -e

# Spot macroscopic problems on LAMP servers.
# This script lives @ https://github.com/eraclitux/lampalyzer

# Copyright 2014 Andrea Masi eraclitux@gmail.com
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

REDSTART="\033[31m"
YELLOWSTART="\033[33m"
BLUESTART="\033[34m"
COLORSTOP="\033[0m"

cprint() {
    if [ $COLORS_ENABLED -eq 0 ]; then
        echo $2
        return
    fi
    if [ "$1" = "RED" ]; then
        echo $REDSTART$2$COLORSTOP
        return
    fi
    if [ "$1" = "YELLOW" ]; then
        echo $YELLOWSTART$2$COLORSTOP
        return
    fi
    if [ "$1" = "BLUE" ]; then
        printf "%b" $BLUESTART$2$COLORSTOP
        echo $BLUESTART$2$COLORSTOP
        return
    fi
}

general_checks() {
    # Check if colors are suppoted by the terminal in use
    # FIXME always no colors executing like: ssh root@host 'sh' < lampalizer.sh
    # pseudo-terminal will not be allocated because stdin is not a terminal.
    COLORS=`tput colors 2> /dev/null`
    if [ $? = 0 ] && [ $COLORS -gt 2 ]; then
        COLORS_ENABLED=1
    else
        COLORS_ENABLED=0
    fi
    FQDN=`hostname -f`
    cprint BLUE "############################"
    cprint BLUE "##### ${FQDN}"
    cprint BLUE "############################"
    echo "[INFO] Local date: "$(date)
    echo "[INFO] Uptime:"$(uptime)
}

check_awk() {
    if ! [ -x /usr/bin/awk ]; then
        cprint RED "[FATAL] This script needs awk to be installed."
        exit 1
    fi
}

depency_check() {
    check_awk
}

get_load() {
    LOAD=`cat /proc/loadavg | awk '{print $1}'`
}

get_cores() {
    # nproc is not portable
    #CORES=`nproc`
    CORES=`cat /proc/cpuinfo | grep processor | wc -l`
    echo "[INFO] Total cores: $CORES"
}

check_load() {
    get_load
    get_cores
    RESULT=$(awk 'BEGIN{ print "'$LOAD'"<"'$CORES'" }')
    if ! [ $RESULT -eq 1 ]; then
        cprint YELLOW "[WARNING] High load: "$LOAD
    fi
}

check_memory() {
    MEM_TOT=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    echo "[INFO] Total memory: "$(($MEM_TOT/1024))" KB"
    # used - (-/+ buffers/cache)
    MEM_REALLY_USABLE=`free | awk 'NR==3 {print $4}'`
    if [ $MEM_REALLY_USABLE -lt 200000 ]; then
        cprint YELLOW "[WARNING] Usable memory is low: ${MEM_REALLY_USABLE}KB"
    fi
    output=`vmstat  1 2 | tail -1 | awk '{print $7,$8}'`
    if [ "$output" != "0 0" ];then
        cprint YELLOW "[WARNING] Swapping!"
    fi
}

check_disks_usage() {
    # Check space occupation
    output=$(df -h | tail -n +2)
    # This will change IFS in a sub shell so no need to change back!
    # "\n" doesn't work
    (
    IFS="
"
    for line in $output; do
        y=`echo $line | awk '{print $5}'`
        if [ ${y%?} -gt 90 ]; then
            cprint YELLOW "[WARNING] Critical disk usage:"
            echo $line
        fi
    done
    )
    # Check for inodes usage
    output=$(df -i | tail -n +2)
    # This will change IFS in a sub shell so no need to change it back!
    # "\n" doesn't work
    (
    IFS="
"
    #FIXME "-" in df -i output for fat partition
    for line in $output; do
        y=`echo $line | awk '{print $5}'`
    # ignore errors like test "-" as number
        if [ ${y%?} -gt 90 2> /dev/null ]; then
            cprint YELLOW "Critical inode usage:"
            echo $line
        fi
    done
    )
}

get_os() {
    # Get OS type and set corresponding variables
    if [ -f /etc/debian_version ]; then
        if [ -x /usr/bin/lsb_release ]; then
            OS_VERSION=`lsb_release -d | awk '{print $2,$3}'`
        else
            OS_VERSION=`cat /etc/debian_version`
        fi
        OS="debian"
        APACHE_NAME="apache2"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"
        OS_VERSION=`cat /etc/redhat-release`
        APACHE_NAME="httpd"
    else
        cprint YELLOW "[WARNING] Unrecognized operating system."
        OS="unknown"
        APACHE_NAME="apache2"
        OS_VERSION="unknown"
    fi
    echo "[INFO] System type: ${OS}. Version: ${OS_VERSION}"
}

plesk_checks() {
    if [ -r /opt/psa/version ]; then
        PLESK_VERSION=`cat /opt/psa/version`
        echo "[INFO] Found Parralles Plesk $PLESK_VERSION"
    else
        return
    fi
    if [ -x /usr/local/psa/bin/admin ]; then
        PLESK_PSWD=`/usr/local/psa/bin/admin --show-password`
        echo "[INFO] Plesk admin password: ${PLESK_PSWD}"
    fi
    echo "[INFO] https://${FQDN}:8443"
}

is_apache_running() {
    # FIXME are pgrep, pidof portable?
    pidof $APACHE_NAME > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        cprint RED "[WARNING] Apache process not found!"
    fi
}

check_max_clients() {
    if [ "$OS" = "debian" ]; then
        apache_log_path="/var/log/apache2/access.log"
        apache_errorlog_path="/var/log/apache2/error.log"
    elif [ "$OS" = "redhat" ]; then
        apache_log_path="/var/log/httpd/access_log"
        apache_errorlog_path="/var/log/httpd/error_log"
    fi
    if ! [ -f "$apache_log_path" ]; then 
        cprint YELLOW "[WARNING] Apache's access log not found/readable at ${apache_log_path}"
        return
    fi
    if ! [ -f "$apache_errorlog_path" ]; then 
        cprint YELLOW "[WARNING] Apache's error log not found/readable at ${apache_errorlog_path}"
        return
    fi
    output=`grep -i maxclients $apache_errorlog_path | tail -1`
    if ! [ -z "$output" ]; then
        cprint YELLOW "[WARNING] Apache has reached MaxClients!"
        echo $output
    fi
}

check_apache() {
    # Check for Apache issues
    echo "### Apache checks"
    is_apache_running
    check_max_clients
}

check_php() {
    echo "### Php checks"
    which php > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        php -v
    else
        cprint YELLOW "[WARNING] Php executable not found!"
    fi
}

checks_connections() {
    # TODO ipv6 support
    if [ "$OS" = "debian" ]; then
        # Seems that -4 is not supported on RHEL like systems
        output=`netstat -ntu -4 | tail -n +3 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -3`
        echo "[INFO] Top ipv4 connections:"
    else 
        output=`netstat -ntu | tail -n +3 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -3`
        echo "[INFO] Top connections:"
    fi
    (
    IFS="
"
    for line in $output; do
         echo $line
    done
    )
}

#NOTE mysqladmin -uadmin -p processlist --verbose
check_mysql() {
    echo "### Mysql checks"
    which mysql > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "[INFO] "`mysql -V`
    else
        cprint YELLOW "[WARNING] Mysql client not found!"
    fi

    pidof mysqld > /dev/null 2>&1
    if ! [ $? -eq 0 ]; then
        cprint YELLOW "[WARNING] Mysql not running!"
        return
    fi
    if ! [ -z "$PLESK_PSWD" ]; then
        limit=`mysql -uadmin -p$(cat /etc/psa/.psa.shadow) -e 'SELECT @@max_connections'`
        limit=`echo $limit | awk '{print $2}'`
        actual=`mysqladmin -uadmin -p$(cat /etc/psa/.psa.shadow) extended-status | grep -i max_used | awk '{print $4}'`
    if [ $actual -ge $limit ]; then
        cprint RED "[WARNING] Mysql reached max connections."
    fi
    fi

}

check_spam () {
    # Queue limit 
    echo "### MailQueue checks"
    QLIMIT=50
    # Check postfix queue
    which postqueue > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        QSIZE=$(postqueue -p | tail -n 1 | cut -d' ' -f5)
        if [ -n "$QSIZE" ]; then
            if [ $QSIZE -gt $QLIMIT ]; then
                cprint YELLOW "[WARNING] Postfix mailqueue is too big. $QSIZE messages in queue. Possible spam "
            else
                echo "[INFO] Postfix messages in queue: $QSIZE"
            fi
        else
            QSIZE=0
            echo "[INFO] Postfix messages in queue: $QSIZE"
        fi
    fi

    # Check exim queue
    which exim > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        QSIZE=$(exim -bpc)
        if [ $QSIZE -gt $QLIMIT ]; then
            cprint YELLOW "[WARNING] Exim mailqueue is too big. $QSIZE messages in queue. Possible spam "
        else
            echo "[INFO] Exim messages in queue: $QSIZE"
        fi
    fi

    # Check qmail queue
    if [ -f /var/qmail/bin/qmail-qstat ]; then
        QQSIZE=$(/var/qmail/bin/qmail-qstat |head -n 1 | cut -d' ' -f4)
    elif [ -f /opt/qmail/bin/qmail-qstat ]; then
        QQSIZE=$(/opt/qmail/bin/qmail-qstat |head -n 1 | cut -d' ' -f4)
    fi

    if [ -n "$QQSIZE" ]; then
        if [ $QQSIZE -gt $QLIMIT ]; then
            cprint YELLOW "[WARNING] Qmail mailqueue is too big. $QQSIZE messages in queue. Possible spam "
        else
            echo "[INFO] Qmail messages in queue: $QQSIZE"
        fi
    fi
}

security_checks() {
    echo "### Basic security checks"
    # Performs basics checks against:
    # CVE-2014-6271
    env x='() { :;}; echo vulnerable' bash -c "Checking..." 2> /dev/null | grep -q vulnerable;
    if [ $? -eq 0 ]; then
        cprint YELLOW "[DANGER] Vulnerable to CVE-2014-6271!"
    fi
}

######################################################
# Main
######################################################

general_checks
depency_check
check_load
check_disks_usage
check_memory
get_os
plesk_checks
checks_connections
check_php
check_mysql
check_apache
check_spam
security_checks

# vim:ts=4:sw=4:sts=4:et
