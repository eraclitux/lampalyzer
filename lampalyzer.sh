#!/bin/sh

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
    output=`hostname -f`
    cprint BLUE "############################"
    cprint BLUE "##### "$output
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
        cprint YELLOW "[WARNING] Usable memory is low: "$MEM_REALLY_USABLE"KB"
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
        echo "[INFO] Debian compatible! "$OS_VERSION
        OS="debian"
        APACHE_NAME="apache2"
    elif [ -f /etc/redhat-release ]; then
        OS="redhat"
        OS_VERSION=`cat /etc/redhat-release`
        APACHE_NAME="httpd"
        echo "[INFO] Red-Hat compatible! "$OS_VERSION
    else
        cprint YELLOW "[WARNING] Unrecognized operating system."
        OS="unknown"
        APACHE_NAME="apache2"
    fi
}

get_plesk_info() {
    if [ -r /opt/psa/version ]; then
        PLESK_VERSION=`cat /opt/psa/version`
        echo "[INFO] Found Parralles Plesk $PLESK_VERSION"
    fi
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
        #FIXME what todo here?
        cprint YELLOW "[WARNING] Apache's access log not found/readable at "$apache_log_path
    fi
    if ! [ -f "$apache_errorlog_path" ]; then 
        cprint YELLOW "[WARNING] Apache's error log not found/readable at "$apache_errorlog_path
    fi
    output=`grep -i maxclients $apache_errolog_path | tail -1`
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
        # Seems that -4 is not supported on redhat systems
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
#        y=`echo $line | awk '{print $5}'`
#        if [ ${y%?} -gt 90 ]; then
#            cprint YELLOW "Critical disk usage:"
#            echo $line
#        fi
    done
    )
}

######################################################
# Mysql
######################################################
# mysqladmin -uadmin -p processlist --verbose
# mysqladmin -uadmin -p extended-status
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
    fi
}

security_checks() {
    # Performs basics checks against:
    # CVE-2014-6271
    env x='() { :;}; echo vulnerable' bash -c "Checking..." 2> /dev/null | grep -q vulnerable;
    if [ $? -eq 0 ]; then
            echo "[DANGER] Vulnerable to CVE-2014-6271!"
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
checks_connections
check_php
check_mysql
check_apache
security_checks
