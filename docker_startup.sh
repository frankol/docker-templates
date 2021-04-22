#!/bin/bash
# CPX Startup script 
# FILE:         $Id$
# LAST CHECKIN: $Author$
#               $DateTime$
#
# Copyright 1998-2020 Citrix Systems, Inc. All rights reserved.
# This software and documentation contain valuable trade
# secrets and proprietary property belonging to Citrix Systems, Inc.
# None of this software and documentation may be copied,
# duplicated or disclosed without the express
# written permission of Citrix Systems, Inc.
#
# Options:      NONE

##################################################################
#
# Docker Startup Script
#
##################################################################

# Few environment variables can be passed to control CPX networking
# behaviour in host mode.
# 1. NS_NETMODE : Possible Values: HOST, IP_PER_CONTAINER
#	HOST: CPX is operating in host mode and has access
#	to host networking. CPX installs a new networking namespace
#	'netscaler'.
#	In namespace 'netscaler', CPx creates a private host-local
#	subnet, assigns a IP for self, and installs a gateway on host
#	networking stack.
#	IP_PER_CONTAINER: If CPX is operating in environments where CPX
#	is assigned an IP which is directly accessible from outside
#	instead of going through host IP (and published port on host),
#	then set NS_NETMODE=IP_PER_CONTAINER to indicate MAS to connect
#	to CPX directly using CPX IP.
#
# 2. NS_IP : In 'IP/mask' mode. e.g. '10.20.30.40/24'. This env is only
#	valid in case of 'NS_NETMODE=HOST'. Instead of using default
#	subnet/NSIP i.e. '192.168.1.2/24', you can modify host-local IP
#	and subnet to desired free private host-local IP. If mask is
#	skipped then default mask of 24 is assumed.
#
# 3. NS_GATEWAY : This env is only valid in case of 'NS_NETMODE=HOST'.
#	By default first IP in host-local private subnet is used as
#	gateway IP. But behavior can be modified to use any other IP by
#	supply NS_GATEWAY env variable. e.g.
#	-e NS_IP=10.20.30.40/24 -e NS_GATEWAY=10.20.30.41

FAILURE_EXIT_CODE=1

# Command line arguments. It is used for kubernetes ingress class
CMD_LINE_ARGS=$@

BOOTUP_LOGS=/var/log/boot.log
touch $BOOTUP_LOGS
#
# Variable is used to define
# List of interfaces to be attached
# by PE.
#
user_intf=""

ns0dev="ns0"
ns1dev="ns1"
ns2dev="ns2"

#Checking if CPX is running on redhat
if [ -f "/etc/redhat-release" ]
then
	REDHAT=1
else
	REDHAT=0
fi
disable_daemons(){
    if ! [ -n "$NO_SSHD" ]; then
        NO_SSHD=1
    fi

    if ! [ -n "$NO_NSAAAD" ]; then
        NO_NSAAAD=1
    fi

    if ! [ -n "$NO_RSYSLOG" ]; then
        NO_RSYSLOG=1
    fi

    if ! [ -n "$NO_MONIT" ]; then
        NO_MONIT=1
    fi

    if ! [ -n "$NO_NSTRACEAGGREGATOR" ]; then
        NO_NSTRACEAGGREGATOR=1
    fi

    if ! [ -n "$NO_SNMPD" ]; then
        NO_SNMPD=1
    fi

    if ! [ -n "$NO_ASLEARN" ]; then
        NO_ASLEARN=1
    fi

    if ! [ -n "$NO_IMI" ]; then
        NO_IMI=1
    fi
    if ! [ -n "$NO_CRON" ]; then
        NO_CRON=1
    fi
    if ! [ -n "$NO_SYNC" ]; then
        NO_SYNC=1
    fi
    if ! [ -n "$NO_DATADAEMON_NSCOLLECT" ]; then
        NO_DATADAEMON_NSCOLLECT=1
    fi
    if ! [ -n "$NO_NSMAP" ]; then
        NO_NSMAP=1
    fi

}

export CPX_MAXIMUM_MEMORY=$CPX_MAX_MEM
echo "cpx_maximum_memory is  $CPX_MAXIMUM_MEMORY" >> $BOOTUP_LOGS

lwcpx_optim_params(){

    HTTPD_START_SERVERS=1
    HTTPD_MIN_SPARE_SERVERS=1
    NSCPX_IS_LW_CPX=1

}

BIN=/var/netscaler/bins

enable_metricscollector(){
echo "Metricscollector is enabled" >> $BOOTUP_LOGS
$NETNS $BIN/metricscollector -l 192.0.0.1 -a 192.0.0.2
}

#Setting default values of cpx environment variables
if ! [ -n "$NS_CPX_LITE" ]; then
    NS_CPX_LITE=0
    lwcpx_optim_params
    echo "NS_CPX_LITE is not set" >> $BOOTUP_LOGS

elif [ $NS_CPX_LITE -eq 1 ]; then
    echo "Setting up environment for cpx lite" >> $BOOTUP_LOGS
    CPX_CORES=1
    CPX_MAX_MEM=256
    CPX_NUM_PNICS=2
    disable_daemons
    lwcpx_optim_params
    enable_metricscollector

#elif [ $NS_CPX_LITE -eq 3 ]; then  #Support of all ingress features with lwcpx optimizations
#   echo "Setting up environment for cpx lite=3" >> $BOOTUP_LOGS
#    lwcpx_optim_params
else
    echo -e "NS_CPX_LITE value should be either 0 or 1. Exiting container"
    exit $FAILURE_EXIT_CODE

fi


if ! [ -n "$NO_NSAAAD" ]; then
	NO_NSAAAD=0
        echo "NO_NSAAAD is not set" >> $BOOTUP_LOGS
else
        echo "----NO_NSAAAD is set----" >> $BOOTUP_LOGS
fi
if ! [ -n "$NO_RSYSLOG" ]; then
	NO_RSYSLOG=0
        echo "NO_RSYSLOG is not set" >> $BOOTUP_LOGS
else
        echo "----NO_RSYSLOG is set----" >> $BOOTUP_LOGS
fi
if ! [ -n "$NO_NSTRACEAGGREGATOR" ]; then
	NO_NSTRACEAGGREGATOR=0
        echo "NO_NSTRACEAGGREGATOR is not set" >> $BOOTUP_LOGS
else
        echo "----NO_NSTRACEAGGREGATOR is set----" >> $BOOTUP_LOGS
fi
if ! [ -n "$NO_SSHD" ]; then
	NO_SSHD=0
        echo "NO_SSHD is not set" >> $BOOTUP_LOGS
else
	echo "NO_SSHD is set" >> $BOOTUP_LOGS
fi

if ! [ -n "$NO_SNMPD" ]; then
	NO_SNMPD=0
        echo "NO_SNMPD is not set" >> $BOOTUP_LOGS
else
	echo "NO_SNMPD is set" >> $BOOTUP_LOGS
fi

if ! [ -n "$NO_ASLEARN" ]; then
	NO_ASLEARN=0
    echo "NO_ASLEARN is not set" >> $BOOTUP_LOGS
else
	echo "NO_ASLEARN is set" >> $BOOTUP_LOGS
fi

if ! [ -n "$NO_IMI" ]; then
    NO_IMI=0
    echo "NO_IMI is not set" >> $BOOTUP_LOGS
else
    echo "NO_IMI is set" >> $BOOTUP_LOGS
fi
if ! [ -n "$NO_CRON" ]; then
    NO_CRON=0
    echo "NO_CRON is not set " >> $BOOTUP_LOGS
else
    echo "NO_CRON is set " >> $BOOTUP_LOGS
fi
if ! [ -n "$NO_SYNC" ]; then
    NO_SYNC=0
    echo "NO_SYNC is not set" >> $BOOTUP_LOGS
else
    echo "NO_SYNC is set" >> $BOOTUP_LOGS
fi

if ! [ -n "$NSCPX_IS_LW_CPX" ]; then
	NSCPX_IS_LW_CPX=0
	echo "NSCPX_IS_LW_CPX is not set" >> $BOOTUP_LOGS
else
	echo "NSCPX_IS_LW_CPX is set" >> $BOOTUP_LOGS
fi

if [ $NS_CPX_LITE -eq 1 ] || [ $NS_CPX_LITE -eq 2 ]; then
	echo "LW BUILTIN IS ACTIVE" >> $BOOTUP_LOGS
	ln -s -f /var/netscaler/lib32/ns32/libnscli90lw.so /var/netscaler/lib32/ns32/libnscli90.so
else 
    echo "LW BUILTIN IS NOT ACTIVE" >> $BOOTUP_LOGS
fi

if ! [ -n "$NO_MONIT" ]; then
	NO_MONIT=0
	echo "NO_MONIT is not set" >> $BOOTUP_LOGS
else
	echo "NO_MONIT is set" >> $BOOTUP_LOGS
fi

if ! [ -n "$NO_DATADAEMON_NSCOLLECT" ]; then
	NO_DATADAEMON_NSCOLLECT=0
	echo "NO_DATADAEMON_NSCOLLECT is not set" >> $BOOTUP_LOGS
else
	echo "NO_DATADAEMON_NSCOLLECT is set" >> $BOOTUP_LOGS
fi

if ! [ -n "$NO_NSMAP" ]; then
    NO_NSMAP=0
    echo "NO_NSMAP is not set" >> $BOOTUP_LOGS
else
    echo "NO_NSMAP is set" >> $BOOTUP_LOGS
fi
# Default yield behavior in case varaible is not set by user or set with errors.
_CPX_YIELD=1

# While initializing CPX, we tend to remove IP from container. 
# If this is done prior to kube health monitoring, kube declares the pod as killed.
# Sleep to enable health monitoring to succeed, post which CPX initialization can be done.
sleep 2

# Parse CPX_CONFIG variable and set the variables to the appropriate
# values
if  ! [ -z ${CPX_CONFIG+x} ]; then
	_CPX_YIELD=$(echo $CPX_CONFIG | grep -Po '(?<="YIELD":")[^"]*')
	if ! [[ "${_CPX_YIELD,,}" =~ ^(yes|no)$ ]]; then
		_CPX_YIELD=1
	else
		if [[ "${_CPX_YIELD,,}" =~ ^(yes)$ ]]; then
			_CPX_YIELD=1
		else
			_CPX_YIELD=0
		fi
	fi
fi

# Export CPX variable for being used by NSPPE
export _CPX_YIELD=$_CPX_YIELD

# Validate IPv4 addresses
# Returns 0 if IPv4 address is valid otherwise 1
function validate_ipv4()
{
    local  ip=$1
    local  res=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255  && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        res=$?
    fi
    return $res
}

# Validate HOST which is IPv4 address of host. If IPv4 address 
# validation fails then reset the variable so PE won't set invalid address
if [ ! -z ${HOST} ]; then
	res=$(validate_ipv4 HOST)
	if [ $res -ne 0 ]; then
		HOST=""
		echo "Warning: HOST is not a valid IPv4 address. HA feature might not work in scenarios with port forwarding on host."
	fi
fi
NETNS=""
if [ "$NS_NETMODE" == "HOST" ]; then
	NETNS="ip netns exec netscaler"
	function detach_intf()
	{
		for name in $1
		do
			if [ "$name" != "$ns0dev" ]; then
				ip netns exec netscaler ip link set $name netns 1
				#Handle error case
				ret_code=$?
				if ! [ $ret_code -eq 0 ]; then
					echo "Warning:failed to unlink interface[$name]  with return code $ret_code"
				fi
			fi
		done
	}
	function release_namespace()
	{
		detach_intf "$1"
		ip netns delete netscaler
	}

fi
startup_conf='/var/netscaler/conf/.nsppe_startup_conf'
signal_handler() {

        echo "signal_handler: Received SIGNAL"

	#Call cleanup function
        cleanup

        echo "signal_handler: Quitting monit"
	monit quit >> $BOOTUP_LOGS
	exit 0
}

cleanup() {

        echo "cleanup: Cleaning up before Exiting"
	if [[ $CPX_REGISTRATION_EXIT_STATUS -eq 0 ]]; then
		cpx_registration "deregister"
	fi
	# Release the license if acquired.
	if [ -f /nsconfig/pooledlicense.conf ]; then
		$NETNS $BIN/cli_script.sh "unset capacity -bandwidth"
		$NETNS $BIN/cli_script.sh "unset capacity -platform"
		$NETNS $BIN/cli_script.sh "rm licenseserver $LS_IP"
	fi

	#cleanup
	if [ "$NS_NETMODE" == "HOST" ]; then
		cpx_delete_iptables_rules
		release_namespace "$user_intf"
	fi
	if [ $NO_CRON -ne 1 ]; then
		kill -9 $(cat /var/run/crond.pid)
		rm -f /var/run/crond.pid
	fi
	if [ $NO_RSYSLOG -ne 1 ]; then
		if [ $REDHAT -eq 1 ]
		then
			kill -9 $(cat /var/run/syslogd.pid)
			rm -f /var/run/syslogd.pid
		else
			kill -9 $(cat /var/run/rsyslogd.pid)
			rm -f /var/run/rsyslogd.pid
		fi
    fi
    if [ $NO_SYNC -ne 1 ]; then
		kill -9 $(cat /var/nslog/nsrsyncd.pid)
		rm -f /var/nslog/nsrsyncd.pid
	fi
    if [ $NO_NSMAP -ne 1 ]; then
		kill -9 $(cat /var/nslog/nsmap.pid)
		rm -f /var/nslog/nsmap.pid
	fi

	# Sometimes monits pid file still exists after monit exits.
	# This creates issue when container is restarted.
	if [ $NO_MONIT -ne 1 ]; then
		rm -f /var/run/monit.pid
	fi

	# Delete IP table rule for nodelocal DNS
	if [ ! -z ${CPX_DNS_SVC_IP} ]; then
		nsip=$(nsenter --net=/netns/default/net iptables-save -t nat | grep cpx_nodelocal_dns | awk '{print $12}')
		echo "nsenter --net=/netns/default/net iptables -t nat -D PREROUTING -d $CPX_DNS_SVC_IP -j DNAT --to-destination $nsip -m comment --comment cpx_nodelocal_dns"
		if [ ! -z $nsip ]; then
			nsenter --net=/netns/default/net iptables -t nat -D PREROUTING -d $CPX_DNS_SVC_IP -j DNAT --to-destination $nsip -m comment --comment cpx_nodelocal_dns
		fi
	fi

}

# Stop CPX, if critical prerequisites are missing from docker run
# comamnd
non_privileged_mode_handler()
{
	echo $1
	echo "Exiting CPX"
	exit $FAILURE_EXIT_CODE
}

trap signal_handler SIGTERM

# Checking for EULA acceptance
function PRINT_EULA_MSG {
	echo "CPX did not run due to missing environment variables. To enable CPX, please provide any one of the following:";
	echo -e "\n \t a. Pass -e EULA=yes as an environment variable. This acknowledges that you have read the EULA which is available here: https://www.citrix.com/downloads/netscaler-adc/container-based-adc/netscaler-cpx-thank-you.html";
	echo -e "\n \t b. Pass -e LS_IP=<IP v4 address or FQDN>. This is the location of a license server reachable from this Docker host.\n";
	echo -e "\n \t c. Pass -e LOCAL_LICENSE=yes. This will bring-up CPX in local-file based licensing mode.\n";
	echo "Exiting CPX"
	exit $FAILURE_EXIT_CODE
}
CPX_LOCAL_LICENSED=0
if [ -z ${EULA} ] && [ -z ${LS_IP} ] && [ -z ${LOCAL_LICENSE} ]; then 
	PRINT_EULA_MSG
else
	if ! [ -z ${EULA} ]; then
		if ! [[ "${EULA,,}" =~ ^(yes|true|ok)$ ]]; then
			PRINT_EULA_MSG
		elif ! [ -z ${LOCAL_LICENSE} ]; then
			if ! [[ "${LOCAL_LICENSE,,}" =~ ^(yes|true|ok)$ ]]; then
				PRINT_EULA_MSG
			else
				LOCAL_LICENSE=1
				export CPX_LOCAL_LICENSED=$LOCAL_LICENSE
				echo -e "\n Local license specified. Starting CPX\n"
			fi
		else
			echo -e "\n User has accepted EULA. Starting CPX \n"
		fi
	else
		if ! [ -z ${LOCAL_LICENSE} ]; then
			if ! [[ "${LOCAL_LICENSE,,}" =~ ^(yes|true|ok)$ ]]; then
				PRINT_EULA_MSG
			else
				LOCAL_LICENSE=1
				export CPX_LOCAL_LICENSED=$LOCAL_LICENSE
				echo -e "\n Local license specified. Starting CPX\n"
			fi
		else
			echo -e "\n License Server IP = " $LS_IP "Starting CPX\n"
		fi
	fi
fi

if [ $NS_CPX_LITE -eq 1 -a $LOCAL_LICENSE -eq 1 ]; then
	echo -e "\n Local-file based licensing is not supported in cpx lite. Stopping Container"
	exit $FAILURE_EXIT_CODE
elif [ $LOCAL_LICENSE -eq 1 -a ! -z ${LS_IP} ]; then
	echo "Incorrect combination. Both LOCAL_LICENSE and LS_IP specified."
	exit $FAILURE_EXIT_CODE
fi

if [ -z ${CPX_CORES} ] ; then
	echo -e "\n CPX_CORES Environment variable is not set. Stopping Container"
	exit $FAILURE_EXIT_CODE
else
	if [ $CPX_CORES -lt 1 ] || [ $CPX_CORES -gt 20 ]; then
		echo -e "\n CPX_CORES can not be less then 1 or greater then 20. Stopping Container"
		exit $FAILURE_EXIT_CODE
	fi
fi

# CPX Sidecar mode for istio usecase.
# NSIP will not be exposed to ns2 interface and the processing in PE will be
# done via normal packet processing path. PROCESS_LINUX() will not be called
# for rx traffic on interface ns1
if [[ "${CPX_SIDECAR_MODE,,}" =~ ^(yes|true)$ ]]; then
	export _CPX_SIDECAR_MODE=1
        export NS_MGMT_DEPLOYMENT_MODE='sidecar'
else
	export _CPX_SIDECAR_MODE=0
fi

# In sidecar environment, application sends packet to external service's FQDN
# which might get resolved to dummy/non-existent IP, and sidecar CPX needs to redirect
# it to designated endpoint. In such cases, 3 way handshake with DNS resolved IP
# must be handled by PE itself instead of probing the resolved-endpoint
if [[ $_CPX_SIDECAR_MODE == 1 ]]  && [[ "${CPX_DISABLE_PROBE,,}" =~ ^(yes|true)$ ]]; then
	export _CPX_DISABLE_PROBE=1
else
	export _CPX_DISABLE_PROBE=0
fi

# BUG0674569: This is a workaround for lped crash issue
# Need to be reverted back after complete fix
python - <<END
import socket
with open("/etc/hosts", 'r') as hosts:
  with open("/tmp/hosts.new", "w") as hosts_new:
    for line in hosts:
        addr=line.split()[0:]
        try:
            socket.inet_aton(addr[0])
            hosts_new.write(line)
        except socket.error:
            print 'ignoring ' +str(addr)
            continue
END
cp -f /tmp/hosts.new /etc/hosts

# Creating CPX directory structure

CPX_MOUNT=/cpx
NSLOG_DIR=$CPX_MOUNT/nslog
NSTRACE_DIR=$CPX_MOUNT/nstrace
NEWNSLOG_DIR=$CPX_MOUNT/nslog/newnslog
APPFLOW_DIR=$CPX_MOUNT/nslog/appflow
NSCONFIG_DIR=$CPX_MOUNT/nsconfig
CONFIG_SSL_DIR=$CPX_MOUNT/nsconfig/ssl
NS_SSL_DIR=$CPX_MOUNT/netscaler/ssl
DNS_DIR=$CPX_MOUNT/nsconfig/dns
MONITORS_DIR=$CPX_MOUNT/nsconfig/monitors
CRASH_DIR=$CPX_MOUNT/crash
CPXLOG_DIR=$CPX_MOUNT/log
NSGUI_DIR=/var/netscaler/bins/ns_gui
LICENSE_DIR=$CPX_MOUNT/nsconfig/license
DIRS=("$NEWNSLOG_DIR" "$APPFLOW_DIR" "$CONFIG_SSL_DIR" "$NS_SSL_DIR" "$DNS_DIR" "$MONITORS_DIR" "$CRASH_DIR" "$NSTRACE_DIR" "$LICENSE_DIR")

mkdir -p /etc/monit/conf.d/ /etc/monit.d/
cp -r /etc/monit.d/* /etc/monit/conf.d/

for dir in "${DIRS[@]}"; do
	if [ ! -d "$dir" ]; then
		mkdir -p $dir
	fi
done

if [ ! -d $NSGUI_DIR ]; then
	mkdir -p $NSGUI_DIR
	ln -s /var/netscaler/contrib/httpd/www/htdocs/admin_ui $NSGUI_DIR/admin_ui
fi

#Changing log directory to /cpx/log from /var/log for volume mount purpose
if [ ! -d $CPXLOG_DIR ]; then
	echo "Moving /var/log to $CPX_MOUNT" >> $BOOTUP_LOGS
	mv /var/log $CPX_MOUNT
else
	echo "Moving logs from /var/log/boot.log to /cpx/log/boot.log. Removing /var/log" >> $BOOTUP_LOGS
	cat $BOOTUP_LOGS >> /cpx/log/boot.log
	rm -rf /var/log
fi
ln -sf $CPXLOG_DIR /var/log
echo "Soft-linking /var/log to /cpx/log" >> $BOOTUP_LOGS

if [ ! -d /nsconfig ]
then
    ln -s $NSCONFIG_DIR /nsconfig
fi

if [ ! -d /var/crash ]
then
    ln -s $CRASH_DIR /var/crash
fi

if [ ! -d /var/nslog ]
then
    ln -s $NSLOG_DIR /var/nslog
fi

if [ ! -d /var/nstrace ]
then
    ln -s $NSTRACE_DIR /var/nstrace
fi

if [ ! -d /netscaler ]
then
    ln -s /var/netscaler/bins /netscaler
fi

if [ ! -d /var/netscaler/ssl ]
then
    ln -s $NS_SSL_DIR /var/netscaler/ssl
fi

if [ $NO_IMI -ne 1 ]; then
	IMISH=/netscaler/imish
	if [[ -f $IMISH ]] && ! [[ -f /netscaler/vtysh ]]; then
		ln -f -s $IMISH /netscaler/vtysh
	fi
fi

#Install date to be read by show ns hardware
if [ ! -f /var/netscaler/conf/cpx_install_date ]; then
	echo "INSTALL_DATE=$(date +%D)" > /var/netscaler/conf/cpx_install_date
fi

# For HA. These scripts are required for clear config -f extended+ on secondary node.
if [ ! -d /netscaler/xm ]; then
	mkdir -p /netscaler/xm
	ln -sf /var/netscaler/bins/xm_shared.sh /netscaler/xm/xm_shared.sh
fi

if [ ! -d /netscaler/wi ]; then
	mkdir -p /netscaler/wi
	ln -sf /var/netscaler/bins/clearall.sh /netscaler/wi/clearall.sh
fi

if [ ! -f /nsconfig/.skf ]; then
    cp /var/netscaler/conf/.skf $NSCONFIG_DIR
    chmod 444 $NSCONFIG_DIR/.skf
fi

BOOTUP_CONF=/nsconfig/nsboot.conf
ROUTE_ARP_CONF=/nsconfig/nsroute.conf
CPX_RESTART_CONF=/cpx/conf/nsreboot.conf
CPX_RESTART_CONF_DIR=/cpx/conf/
DEVICEINFO_DIR=/var/deviceinfo
FILE_DEVICE_ID=/var/device_id
FILE_RANDOM_ID=/var/random_id

# 'export' configuration variables
NETSCALER=/netscaler
echo $NETSCALER > /var/run/.NETSCALER 2>> $BOOTUP_LOGS

#NetScaler cert generation
LOG=${NSLOG}
NS_DEFAULT_PARTITIONID=0
NS_SSL_KEYSIZE=2048
NS_GEN_PROG=/netscaler/nssslgen
NS_SSL_DIR=/nsconfig/ssl
NS_ROOT_KEY=${NS_SSL_DIR}/ns-root.key
NS_ROOT_REQ=${NS_SSL_DIR}/ns-root.req
NS_ROOT_CERT=${NS_SSL_DIR}/ns-root.cert
NS_ROOT_SRL=${NS_SSL_DIR}/ns-root.srl
NS_SERVER_KEY=${NS_SSL_DIR}/ns-server.key
NS_SERVER_REQ=${NS_SSL_DIR}/ns-server.req
NS_SERVER_CERT=${NS_SSL_DIR}/ns-server.cert

# Below certs added by Gateway team to provide a 
# unique and persistant certificate by which an NS can be indentified.
NS_SFTRUST_ROOT_KEY=${NS_SSL_DIR}/ns-sftrust-root.key
NS_SFTRUST_ROOT_REQ=${NS_SSL_DIR}/ns-sftrust-root.req
NS_SFTRUST_ROOT_CERT=${NS_SSL_DIR}/ns-sftrust-root.cert
NS_SFTRUST_KEY=${NS_SSL_DIR}/ns-sftrust.key
NS_SFTRUST_REQ=${NS_SSL_DIR}/ns-sftrust.req
NS_SFTRUST_CERT=${NS_SSL_DIR}/ns-sftrust.cert
NS_SFTRUST_ROOT_SRL=${NS_SSL_DIR}/ns-sftrust-root.srl

LOOPIP='192.0.0.2'
#Loop IP Mask is added as a part of 32 Bit Netmask support for Bridgemode CPX
LOOPIP_MASK=24
SNIP='192.0.0.1'

#Netscaler config creation
if [[ -v NS_NETMODE ]]; then
	NS_NETMODE=`echo $NS_NETMODE | tr [a-z] [A-Z]`
fi

if [ "$NS_NETMODE" == "HOST" ]; then
	NS_LB_ROLE="client"
	if ! [[ -v NS_IP ]]; then
		NS_IP="192.168.1.2/24"
	fi
	if [[ ${NS_IP} == *"/"* ]];then
		DOCKER_MASK=$(echo $NS_IP | cut -d '/' -f2)
		DOCKERIP=${NS_IP}
	else
		DOCKER_MASK=24
		DOCKERIP=${NS_IP}/${DOCKER_MASK}
	fi
	NSIP=$(echo $DOCKERIP | cut -d '/' -f1)
else
	{
		until ip link show eth0; do sleep 1; done
	} &> /dev/null
	DOCKERIP=$(ip addr show eth0 | grep 'inet ' | awk '{print $2}')

		#In some kubernetes deployment (GKE) where container crashes, IP is 
        #not provided by kubernetes assuming container will still hold the IP
        #Fix: Extract IP from ns2 interface if eth0 is empty
        if [ -z "$DOCKERIP" ]; then
                echo "eth0 is empty at boot time. Extracting IP from $ns2dev interface"
		NS2_IPS=($(ip addr show $ns2dev | grep 'inet ' | awk '{print $2}'))
                for IP in ${NS2_IPS[@]}
		do
			if [ "$(echo $IP | awk -F '/' '{print $1}')" != "$LOOPIP" ]; then
				DOCKERIP=$IP
                                echo "$DOCKERIP is extracted from $ns2dev interface. This would be configured as NS IP"
			fi
		done
	fi
	DOCKER_MASK=$(echo $DOCKERIP | cut -d '/' -f2)
	NSIP=$(echo $DOCKERIP | cut -d '/' -f1)
fi
NS_IP=$NSIP

if [ "$NS_NETMODE" != "HOST" ]; then
	DEF_ROUTE=$(ip route list dev eth0 | grep default | awk '{print $3}')
        IPGW_ROUTE=$(ip route show | egrep -v 'scope link|default|onlink' | awk '{ print $1 "-" $3}')
        echo "Static Routes via IPGW:" >> $BOOTUP_LOGS
        echo $IPGW_ROUTE >> $BOOTUP_LOGS
fi

CONFIG_FILE=/nsconfig/ns.conf
CPX_ID=$(echo 0x$HOSTNAME|cut -b 1-10 )

declare -a cidrtomask=(\
    "0.0.0.0" "128.0.0.0" "192.0.0.0" "224.0.0.0" "240.0.0.0" "248.0.0.0" "252.0.0.0" "254.0.0.0" "255.0.0.0" \
    "255.128.0.0" "255.192.0.0" "255.224.0.0" "255.240.0.0" "255.248.0.0" "255.252.0.0" "255.254.0.0" "255.255.0.0"\
    "255.255.128.0" "255.255.192.0" "255.255.224.0" "255.255.240.0" "255.255.248.0" "255.255.252.0" "255.255.254.0" "255.255.255.0"\
    "255.255.255.128" "255.255.255.192" "255.255.255.224" "255.255.255.240" "255.255.255.248" "255.255.255.252" "255.255.255.254" "255.255.255.255")
NSIP_MASK=${cidrtomask[$DOCKER_MASK]}

declare -a host_route
declare -a intf_gw_route
declare -a stat_ip
declare -a stat_mac
host_route=()
intf_gw_route=()
stat_mac=()
stat_ip=()

i=0
j=0


INTF_GW_ROUTE=$(ip route list dev eth0 | grep -v default | grep -v src | grep -v via | awk '{print $1}')

#Add all host routes which are GW in Linux as routes in NS
for rt in $INTF_GW_ROUTE
do
		for def_rt in $DEF_ROUTE
		do
				if [ "$def_rt" == "$rt" ]; then
					host_route[i]=$rt
					i=$(($i+1))
				else
					intf_gw_route[j]=$rt
					j=$(($j+1))
		        	fi
		done
done


i=0
#Add all static ARP entries in NS
ARP_CACHE_IPS=$(arp -n | tail -n+2 | awk '{print $1}' )
for ip in $ARP_CACHE_IPS
do
        FLAG=$(arp -n | tail -n+2 | grep $ip | awk '{print $4}')
		if [[ $FLAG =~ [M] ]]; then
				stat_ip[i]=$ip
				stat_mac[i]=$(arp -n | tail -n+2 | grep $ip | awk '{print $3}')
				i=$(($i+1))
		fi
done
#TODO: JIRA Issue NSNET-3906: This is temporary Fix to resolve default GW ARP in Azure.
#NSNET-7450: Seperate BUG has been raised to fix issue from Networking side.
#In this fix, we are probing for MAC of default GW in Linux mode.
#Using that MAC, to add static ARP entry in NS mode
#This routine computes Network address from Given IP and NetMask.
function calculate_nw_addr() {
	IP=$1
	MASK=$2
	m=(${MASK//./ })
	i=(${IP//./ })
	local NW_ADDR="$((${i[0]} & ${m[0]}))"."$((${i[1]} & ${m[1]}))"."$((${i[2]} & ${m[2]}))"."$(((${i[3]} & ${m[3]})))"
	echo "$NW_ADDR"
}

#Maximum MTU supported by PE
MAX_MTU=1500

# Function to set MTU of interface not more than 1500 bytes
function set_intf_mtu()
{
	ifname="$1"
	local MTU=$($NETNS ip link show $ifname | grep -o -E  "mtu \w+" | awk '{print $2}')

	#CPX doesn't support jumbo pkts. setting mtu to MAX_MTU bytes
	if [ $MTU -gt $MAX_MTU ]; then
		echo "MTU of interface $ifname is $MTU" >> $BOOTUP_LOGS
		MTU=$MAX_MTU
		$NETNS ip link set $ifname mtu $MTU
		echo "Setting MTU to $MTU for interface $ifname" >> $BOOTUP_LOGS
	fi

	echo $MTU
}

#Changing Linux N/W, marking PE as default gw
if [ "$NS_NETMODE" == "HOST" ]; then
	# cleanup previous configuration by cpx if any
	ip netns delete netscaler
	ip link delete vethcpx0
	ip link delete $ns1dev
	# veth interface starting with 'veth' are not managed by
	# network manager &&
	ip link add vethcpx0 type veth peer name $ns0dev
	ip link add $ns1dev type veth peer name $ns2dev
	ip link set vethcpx0 up
	ethtool -K vethcpx0 rx off tx off gro off gso off &> /dev/null
	# vethcpx0 is NS represenration on host machine to route packets to 'netscaler' namespace
	# Assign a gateway IP to vethcpx0. If NS_GATEWAY set it to IP given. Else find first free
	# IP in subnet specified by NSIP.
	if ! [[ -v NS_GATEWAY ]]; then
		#convert NSIP and MASK to array i an m and then get subnet and gateway.
		i=(${NSIP//./ })
		m=(${NSIP_MASK//./ })
		NS_GATEWAY="$((${i[0]} & ${m[0]}))"."$((${i[1]} & ${m[1]}))"."$((${i[2]} & ${m[2]}))"."$((1+(${i[3]} & ${m[3]})))"
		if [ $NS_GATEWAY == $NSIP ]; then
			NS_GATEWAY="$((${i[0]} & ${m[0]}))"."$((${i[1]} & ${m[1]}))"."$((${i[2]} & ${m[2]}))"."$((2+(${i[3]} & ${m[3]})))"
		fi
	else
		if [ $NS_GATEWAY == $NS_IP ]; then
			echo "ERROR: NS_IP and NS_GATEWAY both can't be same. "
			exit $FAILURE_EXIT_CODE
		fi
	fi

	# HostMode CPX does not support 32 Bit Netmask
	if [ $DOCKER_MASK -eq 32 ]
	then
		echo "ERROR: Cannot create Hostmode CPX with 32 Bit Netmask. "
		exit $FAILURE_EXIT_CODE
	fi

	ip addr add $NS_GATEWAY/$DOCKER_MASK dev vethcpx0

	# Adding a 'netscaler' namespace to manage netscaler interfaces.
	ip netns add netscaler 1>> $BOOTUP_LOGS 2>&1
	if [ $? -ne 0 ]; then
		non_privileged_mode_handler "For Host mode CPX, please use --privileged=true option with docker run command."
	fi
	ip link set $ns0dev netns netscaler
	ip link set $ns1dev netns netscaler
	ip link set $ns2dev netns netscaler
	$NETNS ip link set $ns0dev up
	$NETNS ip link set $ns1dev up
	$NETNS ip link set lo up
	$NETNS ip link set $ns2dev up
	# NSIP is not exposed to ns2 if CPX_SIDECAR_MODE is enabled
	$NETNS ip addr add $LOOPIP/$DOCKER_MASK dev $ns2dev
	if [ $_CPX_SIDECAR_MODE == 0 ]; then
		$NETNS ip addr add $NSIP/$DOCKER_MASK dev $ns2dev
		$NETNS ip route add default via $NS_GATEWAY dev $ns2dev
	else
		$NETNS ip route add default via $SNIP dev $ns2dev
	fi
	echo "$NETNS ip -6 route add default dev $ns2dev mtu 1500" >> $BOOTUP_LOGS
	$NETNS ip -6 route add default dev $ns2dev mtu 1500
else
	if [ "$(ip addr show eth0 | grep 'inet ' | awk '{print $2}')" ] ; then
		# We have learned all routes and so its fine now to flush. 
		# Also, it is the point where we started configuring routes
		ip route flush dev eth0

		MTU=$(set_intf_mtu eth0)
		MSS=$((MTU - 40))
		# Since NS1 is our interface and we need to forward jumbo packets for internal APP, we should increase NS1 MTU
		ip link add $ns1dev mtu 65535 type veth peer name $ns2dev mtu 65535
		ip addr add $LOOPIP/$LOOPIP_MASK dev $ns2dev
		ip link set $ns1dev up
		ip link set $ns2dev up
		count_route=${#host_route[@]}
		for ((i=$count_route-1;i>=0;--i)); do
			ip route add ${host_route[i]} dev $ns2dev scope link
		done
		# NSIP is not exposed to ns2 if CPX_SIDECAR_MODE is enabled
		# For NS2, MTU should be same as Eth0. To do this, we are setting route with MTU same as eth0
		# Also setting advmss as MSS to avoid any jumbo rx on eth0
		if [ $_CPX_SIDECAR_MODE == 0 ]; then
			ip addr add $NSIP/$DOCKER_MASK dev $ns2dev
			if [ "$DEF_ROUTE" ]; then
				ip route add default via $DEF_ROUTE dev $ns2dev src $NSIP mtu $MTU advmss $MSS
				# In case of Bridgemode CPX, Static ARP is needed because manipulated GatewayIP in Linux is same as NSIP which has /32 Netmask
				arp -Ds $DEF_ROUTE -i $ns2dev eth0 
			fi
		else
			ip route add default via $SNIP dev $ns2dev mtu $MTU advmss $MSS
		fi
		echo "ip -6 route add default dev $ns2dev mtu $MTU advmss $MSS" >> $BOOTUP_LOGS
		ip -6 route add default dev $ns2dev mtu $MTU advmss $MSS
	fi
fi

# sysctls in privileged mode. Fails with CAP_NET_ADMIN, to be provided at CPX creation time
# Making sure that shmget doesnt fail for a big chunk of memory.
sysctl -w kernel.shmmax=1073741824 1>> $BOOTUP_LOGS 2>&1
# Disabling DAD for IPv6 ns2 interface as the SNIP6 with dynamic routing enabled gets inactive
$NETNS sysctl -w net.ipv6.conf.ns2.accept_dad=0 1>> $BOOTUP_LOGS 2>&1
# Set core dump location, only possible this way when running in privileged mode.
sysctl -w kernel.core_pattern=/var/crash/core.%e.%p.%s 1>> $BOOTUP_LOGS 2>&1

# Creating NSPPE startup conf, Read By PE
touch $startup_conf
rm $startup_conf
echo 'r' $NSIP $NSIP_MASK > $startup_conf
echo 'd 0' >> $startup_conf
echo 'j 0' >> $startup_conf
echo 'f 0' >> $startup_conf
echo 'w 0' >> $startup_conf
echo 'h netscaler' >> $startup_conf
echo 'k 0' >> $startup_conf
echo 'l 0' >> $startup_conf
echo 't 0' >> $startup_conf
echo 'm' $SNIP '255.255.255.0' >> $startup_conf
echo 'L loopip' $LOOPIP >> $startup_conf
echo 'i' $CPX_ID >> $startup_conf
echo 'M' $CPX_MAX_MEM >> $startup_conf

# Move tcpdump to a location where we can use it, WORKAROUND:
if [ -f /usr/sbin/tcpdump ]
then
mv /usr/sbin/tcpdump /usr/bin/
fi

# Creating /var/ipconf read by nsnetsvc
touch /var/ipconf
rm /var/ipconf
echo $SNIP > /var/ipconf
echo $LOOPIP >> /var/ipconf

# Change the ns.conf file with new ip if exists
if [ -f $CONFIG_FILE ]
then
	OLD_IP=$(cat $CONFIG_FILE | grep "set ns config -IPAddress" | awk '{print $5}')
	sed -i -e s/$OLD_IP/$NSIP/g "$CONFIG_FILE"
fi

create_sftrust_certificate()
{
	[ -f $NS_SFTRUST_CERT -a -f $NS_SFTRUST_KEY ] && return
	NEW_RANSTRING=`head -c 1024 /dev/urandom |tr -dc 'A-Z' |head -c${1:-6}`
	local COUNTRY="US"
	local STATE="California"
	local LOCATION="San Jose"
	local ORGANIZATION="Citrix Gateway"
	local ORGANIZATIONUNIT="NS SFTrust"
        local COMMONNAME="SFTrust default ""${NEW_RANSTRING}"

	clean_sftrust_certificate

	###
	echo nsstart: `date` ': Creating the RSA root key' >> $BOOTUP_LOGS
	###
	$NETNS $NS_GEN_PROG rsakey $NS_DEFAULT_PARTITIONID $NS_SFTRUST_ROOT_KEY $NS_SSL_KEYSIZE > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the RSA key file: $NS_SFTRUST_ROOT_KEY' >> $BOOTUP_LOGS
		clean_default_certificate
		return
	fi

	###
	echo nsstart: `date` ': Creating the CSR for the root certificate' >> $BOOTUP_LOGS
	###
        #fixed for ENH0451441 and BUG0405363
	$NETNS $NS_GEN_PROG -GUI certreq $NS_DEFAULT_PARTITIONID $NS_SFTRUST_ROOT_REQ -keyFile $NS_SFTRUST_ROOT_KEY -C $COUNTRY -S $STATE -L $LOCATION -O $ORGANIZATION -OU $ORGANIZATIONUNIT -CN $COMMONNAME
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the Certificate Signing Request file (CSR): $NS_SFTRUST_ROOT_REQ' >> $BOOTUP_LOGS
		clean_default_certificate
		return
	fi

	###
	echo nsstart: `date` ': Create the Self-Signed Certificate root certificate' >> $BOOTUP_LOGS
	###
	$NETNS $NS_GEN_PROG cert $NS_DEFAULT_PARTITIONID $NS_SFTRUST_ROOT_CERT $NS_SFTRUST_ROOT_REQ ROOT_CERT -keyFile $NS_SFTRUST_ROOT_KEY -days 1000000
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the Self-Signed Certificate: $NS_SFTRUST_ROOT_CERT' >> $BOOTUP_LOGS
		clean_default_certificate
		return
	fi


	echo nsstart: `date` ': Creating sftrust netscaler certificate for NetScaler StoreFront communication' >> $BOOTUP_LOGS
		
	###
	$NETNS $NS_GEN_PROG rsakey $NS_DEFAULT_PARTITIONID $NS_SFTRUST_KEY $NS_SSL_KEYSIZE > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the RSA key file: $NS_SFTRUST_KEY'  >> $BOOTUP_LOGS
		clean_sftrust_certificate
		return
	fi
	
	###
	echo nsstart: `date` ': Create the CSR for server cert'  >> $BOOTUP_LOGS
	###
#fixed for ENH0451441 and BUG0405363
	$NETNS $NS_GEN_PROG -GUI certreq $NS_DEFAULT_PARTITIONID $NS_SFTRUST_REQ -keyFile $NS_SFTRUST_KEY -C $COUNTRY -S $STATE -L $LOCATION -O $ORGANIZATION -OU $ORGANIZATIONUNIT -CN $COMMONNAME
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating Certificate Signing Request file (CSR): $NS_SFTRUST_REQ'  >> $BOOTUP_LOGS
		clean_sftrust_certificate
		return
	fi

	###
	echo nsstart: `date` ': Create the Server Certificate'  >> $BOOTUP_LOGS
	###
	$NETNS $NS_GEN_PROG cert $NS_DEFAULT_PARTITIONID $NS_SFTRUST_CERT $NS_SFTRUST_REQ SRVR_CERT -CAcert $NS_SFTRUST_ROOT_CERT -CAkey $NS_SFTRUST_ROOT_KEY -CAserial $NS_SFTRUST_ROOT_SRL -days 1000000
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the server Certificate: $NS_SFTRUST_CERT' >> $BOOTUP_LOGS
		clean_sftrust_certificate
		return
	fi
	openssl x509 -outform der -in /nsconfig/ssl/ns-sftrust.cert -out /nsconfig/ssl/ns-sftrust.der
	openssl x509 -in /nsconfig/ssl/ns-sftrust.cert -fingerprint -noout > /nsconfig/ssl/ns-sftrust.sig.tmp
	cat /nsconfig/ssl/ns-sftrust.sig.tmp | awk 'BEGIN {FS="="}; {print $2}' | sed 's/://g' > /nsconfig/ssl/ns-sftrust.sig
	rm /nsconfig/ssl/ns-sftrust.sig.tmp
}

create_default_certificate()
{
# fixed for ENH0451441 and BUG0405363
	[ -f $NS_SERVER_CERT -a -f $NS_SERVER_KEY ] && return
	NEW_RANSTRING=`head -c 1024 /dev/urandom |tr -dc 'A-Z' |head -c${1:-6}`
	local COUNTRY="US"
	local STATE="California"
	local LOCATION="San Jose"
	local ORGANIZATION="Citrix ANG"
	local ORGANIZATIONUNIT="NS Internal"
        local COMMONNAME="default ""${NEW_RANSTRING}"

	clean_default_certificate
	
	echo nsstart: `date` ': Creating default netscaler certificate for NetScaler internal communication' >> $BOOTUP_LOGS
		
	###
	echo nsstart: `date` ': Creating the RSA root key' >> $BOOTUP_LOGS
	###
	$NETNS $NS_GEN_PROG rsakey $NS_DEFAULT_PARTITIONID $NS_ROOT_KEY $NS_SSL_KEYSIZE > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the RSA key file: $NS_ROOT_KEY' >> $BOOTUP_LOGS
		clean_default_certificate
		return
	fi

	###
	echo nsstart: `date` ': Creating the CSR for the root certificate' >> $BOOTUP_LOGS
	###
        #fixed for ENH0451441 and BUG0405363
	$NETNS $NS_GEN_PROG -GUI certreq $NS_DEFAULT_PARTITIONID $NS_ROOT_REQ -keyFile $NS_ROOT_KEY -C $COUNTRY -S $STATE -L $LOCATION -O $ORGANIZATION -OU $ORGANIZATIONUNIT -CN $COMMONNAME
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the Certificate Signing Request file (CSR): $NS_ROOT_REQ' >> $BOOTUP_LOGS
		clean_default_certificate
		return
	fi

	###
	echo nsstart: `date` ': Create the Self-Signed Certificate root certificate' >> $BOOTUP_LOGS
	###
	$NETNS $NS_GEN_PROG cert $NS_DEFAULT_PARTITIONID $NS_ROOT_CERT $NS_ROOT_REQ ROOT_CERT -keyFile $NS_ROOT_KEY -days 1000000
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the Self-Signed Certificate: $NS_ROOT_CERT' >> $BOOTUP_LOGS
		clean_default_certificate
		return
	fi


	###
	echo nsstart: `date` ': Creating the RSA key' >> $BOOTUP_LOGS
	###
	$NETNS $NS_GEN_PROG rsakey $NS_DEFAULT_PARTITIONID $NS_SERVER_KEY $NS_SSL_KEYSIZE > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the RSA key file: $NS_SERVER_KEY' >> $BOOTUP_LOGS
		clean_default_certificate
		return
	fi
	
	###
	echo nsstart: `date` ': Create the CSR for server cert' >> $BOOTUP_LOGS
	###
#fixed for ENH0451441 and BUG0405363
	$NETNS $NS_GEN_PROG -GUI certreq $NS_DEFAULT_PARTITIONID $NS_SERVER_REQ -keyFile $NS_SERVER_KEY -C $COUNTRY -S $STATE -L $LOCATION -O $ORGANIZATION -OU $ORGANIZATIONUNIT -CN $COMMONNAME
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating Certificate Signing Request file (CSR): $NS_SERVER_REQ' >> $BOOTUP_LOGS
		clean_default_certificate
		return
	fi

	###
	echo nsstart: `date` ': Create the Server Certificate' >> $BOOTUP_LOGS
	###
	$NETNS $NS_GEN_PROG cert $NS_DEFAULT_PARTITIONID $NS_SERVER_CERT $NS_SERVER_REQ SRVR_CERT -CAcert $NS_ROOT_CERT -CAkey $NS_ROOT_KEY -CAserial $NS_ROOT_SRL -days 1000000
	if [ $? -ne 0 ]
	then
		echo nsstart: `date` ': Error creating the server Certificate: $NS_SERVER_CERT' >> $BOOTUP_LOGS
		clean_default_certificate
		return
	fi
}

clean_default_certificate()
{
	rm $NS_ROOT_KEY >/dev/null 2>&1
	rm $NS_ROOT_REQ >/dev/null 2>&1
	rm $NS_ROOT_CERT >/dev/null 2>&1
	rm $NS_SERVER_KEY >/dev/null 2>&1
	rm $NS_SERVER_REQ >/dev/null 2>&1
	rm $NS_SERVER_CERT >/dev/null 2>&1
	rm $NS_ROOT_SRL >/dev/null 2>&1
}
clean_sftrust_certificate()
{
	rm $NS_SFTRUST_KEY >/dev/null 2>&1
	rm $NS_SFTRUST_REQ >/dev/null 2>&1
	rm $NS_SFTRUST_CERT >/dev/null 2>&1
}

MAX_INTF_COUNT=10
########
#Variables for duplicate mac addresses due to tagged vlans
########
handle_excluded_intf="false"
exclude_intf_list=""
######
# This function list down interfaces which needs to be excluded
#####
function list_excluded_intf()
{
    vlan_tagged_intf=$(ip -d link show | grep -B 2 vlan |  awk -F': ' '{print $2}' | xargs)
    echo "vlan tagged interfaces are $vlan_tagged_intf"  >> $BOOTUP_LOGS
    exclude_intf_list=$(for intf in $vlan_tagged_intf; do echo $intf | sed 's/@/ /g' | awk '{print $2}'; done | sort -u | xargs)
    if [ ${#exclude_intf_list} -gt 0 ]; then
        echo interfaces which needs to be excluded is $exclude_intf_list  >> $BOOTUP_LOGS
        handle_excluded_intf="true"
    fi
}

if [ "$NS_NETMODE" == "HOST" ]; then
	if  ! [ -z ${CPX_NW_DEV+x} ]; then
		#move all interfaces to netscaler namespace
		env_intf=$(echo "$CPX_NW_DEV" | xargs -n1 | sort -u | xargs)
		intf_count=$(echo $env_intf | wc -w)
		echo "intf_count:$intf_count" >> $BOOTUP_LOGS
		CPX_NUM_PNICS=$(expr "$intf_count" + 1)
		echo "CPX_NUM_PNICS:$CPX_NUM_PNICS" >> $BOOTUP_LOGS
		if [ $intf_count -gt $MAX_INTF_COUNT ]; then
			echo "Error: Reached maximum number of interfaces. . Upto $MAX_INTF_COUNT interfaces are supported"
			echo "Configured Interfaces are $env_intf"
			echo "Exiting CPX"
			exit $FAILURE_EXIT_CODE
		fi
		moved_intf=""
		for name in $env_intf
		do
			ip link set $name netns netscaler
			ret_code=$?
			if ! [ $ret_code -eq 0 ]; then
				echo "Error:failed to link interface[$name]  with return code $ret_code"
				release_namespace "$moved_intf"
				echo "Exiting CPX"
				exit $FAILURE_EXIT_CODE
			fi
			moved_intf=$moved_intf" "$name
			$NETNS ip link set $name up
		done
	fi
	nsppedevs="$ns0dev"
else
	if  ! [ -z ${CPX_NW_DEV+x} ]; then
		echo "Interfaces supplied by env variable CPX_NW_DEV is ignored" >> $BOOTUP_LOGS
	fi
        ## Diamanti change ENH0715729
        # Diamanti network creates interface with vlan tagging
        # In this case, Multiple interfaces  will have same mac causing performance penalty in PE 
        list_excluded_intf
	nsppedevs=""

	#Maximum number of supported interfaces
	if [ -n "$CPX_NUM_PNICS" ]; then
		if [ $CPX_NUM_PNICS -lt 2 ]; then
			CPX_NUM_PNICS=2
		fi
		if [ $CPX_NUM_PNICS -gt 10 ]; then
			CPX_NUM_PNICS=10
		fi
		MAX_INTF_COUNT=$CPX_NUM_PNICS
		echo "MAX_INTF_COUNT = $MAX_INTF_COUNT" >> $BOOTUP_LOGS
		echo "CPX_NUM_PNICS  = $CPX_NUM_PNICS" >> $BOOTUP_LOGS
	fi

fi

if [ $NS_CPX_LITE -eq 1 ]; then
    export CPX_NUM_PNICS=$CPX_NUM_PNICS
fi

#getting interface info
netdevnames=`$NETNS ifconfig -s | sed 's/[ \t].*//;/^\(Iface\|lo\|\)$/d'`
for name in $netdevnames
do
	$NETNS ethtool -K $name rx off tx off gro off gso off &> /dev/null
	if [ "$name" != "$ns2dev" ] &&  [ "$name" != "$ns1dev" ] ; then
		nsppedevs=$nsppedevs" "$name
	fi
done

if [ $handle_excluded_intf == "true" ]
then
    echo "Processing to be excluded interface list which is $exclude_intf_list" >> $BOOTUP_LOGS
    echo "nsppedevs is $nsppedevs" >> $BOOTUP_LOGS
    excluded_intf=""
    for nsppedev in $nsppedevs
    do 
        if [[ $exclude_intf_list = *${nsppedev}* ]] 
            then
                echo Excluding intf $nsppedev  >> $BOOTUP_LOGS
                excluded_intf=$excluded_intf" "$nsppedev 
        fi 
    done
    excluded_intf=$(echo $excluded_intf | xargs -n1 | sort -u | xargs)
    echo "Excluded interface list is $excluded_intf" >> $BOOTUP_LOGS
    list_with_excluded=$(echo "$excluded_intf $nsppedevs" | xargs -n1 | sort)
    included_intf_list=$(uniq -u <(echo "${list_with_excluded}"))
    echo "Included interface list is $included_intf_list" >> $BOOTUP_LOGS
    nsppedevs=$included_intf_list
fi

nsppedevs=`echo "$nsppedevs" | xargs -n1 | sort -u | xargs`

user_intf="$nsppedevs"
export CPX_NW_DEV="$user_intf"

echo "Intf list to be listened by PE is $user_intf" >> $BOOTUP_LOGS

if [ "$NS_NETMODE" != "HOST" ]; then
	intf_count=$(echo $CPX_NW_DEV | xargs | wc -w)
	if [ $intf_count -gt $MAX_INTF_COUNT ]; then
		echo "Error: Reached maximum number of interfaces. . Upto $MAX_INTF_COUNT interfaces are supported"
		echo "Configured Interfaces are $CPX_NW_DEV"
		echo "Exiting CPX"
		exit $FAILURE_EXIT_CODE
	fi
fi

rm -f $BOOTUP_CONF
rm -f $ROUTE_ARP_CONF
#Assigned ip addresses from each interfaces will be SNIP
for name in $user_intf
do
	{
		until $NETNS ip link show $name; do sleep 1; done
	} &> /dev/null
	set_intf_mtu $name
	USER_INTF_IPS=$($NETNS ip addr show $name | grep 'inet ' | awk '{print $2}')
	for USER_INTF_IP in $USER_INTF_IPS
	do
		if ! [ -z "$USER_INTF_IP" ]; then
			USER_INTF_MASK=${cidrtomask[$(echo $USER_INTF_IP | cut -d '/' -f2)]}
			USER_INTF_SNIP=$(echo $USER_INTF_IP | cut -d '/' -f1)
			echo "add ns ip $USER_INTF_SNIP $USER_INTF_MASK -type SNIP" >> $BOOTUP_CONF
			iptables -I INPUT -i $name -j DROP
			# Set interface ARP disabled so that linux kernel will not respond to any ARP request
			ip link set dev $name arp off
			# disable and enable interface so that it will clear configurations, if any
			echo "Disabling and enabling interface $name" >> $BOOTUP_LOGS
			ip link set down dev $name
			ip addr show $name >> $BOOTUP_LOGS
			ip link set up dev $name
			ip addr show $name >> $BOOTUP_LOGS
			echo "Disabled and enabled interface $name" >> $BOOTUP_LOGS
			ip route flush dev $name
		fi
	done
done

# Copying rsyslog configs to the default locations and starting the service
cp /var/netscaler/conf/rsyslog.conf /etc/rsyslog.conf
# /dev/console char device might be absent from the file-system if the CPX is deployed without "-t" or "--tty" option.
# In such scenarios, rsyslogd shouldn't forward logs to /dev/console as it will consume disk space.
if [ -c /dev/console ]; then
	DEV_CONS_PRESENT=$(grep -c '/dev/console' /etc/rsyslog.d/50-default.conf)
	if [ $DEV_CONS_PRESENT -eq 0 ]; then
		sed -i '/\/var\/log\/syslog/a *.*;auth,authpriv.none\t\t\/dev\/console' /etc/rsyslog.d/50-default.conf
	fi
fi

if [ $NO_RSYSLOG -ne 1 ]
then
	$NETNS /usr/sbin/rsyslogd >> $BOOTUP_LOGS
	if [ ! -L /cpx/log/ns.log ]; then
		ln -s /cpx/log/syslog /cpx/log/ns.log
	fi
else
       echo "rsyslogd not started in lightweight cpx" >> $BOOTUP_LOGS
       sed -i '/rsyslog/c\ ' /var/netscaler/conf/cpx_monitrc
fi


# Starting Processes
if [ $NO_SSHD -ne 1 ]; then
	$NETNS /usr/sbin/sshd >> $BOOTUP_LOGS
else
	echo "sshd daemon not started" >> $BOOTUP_LOGS
fi

rm -f /var/netscaler/contrib/httpd/logs/httpd.pid

HTTP_PORT=9080
HTTPS_PORT=9443
#Setting custom mgmthttpport and mgmthttpsport

if ! [ -z ${MGMT_HTTP_PORT} ]; then
	if [ $MGMT_HTTP_PORT -gt 0 ] && [ $MGMT_HTTP_PORT -lt 65535 ]; then
		echo "Applying ${MGMT_HTTP_PORT} as management http port"
		echo "set nsparam -mgmthttpport" $MGMT_HTTP_PORT >> $BOOTUP_CONF
		HTTP_PORT=$MGMT_HTTP_PORT
	else
		echo "MGMT_HTTP_PORT is not in the range of 0 to 65535"
		exit $FAILURE_EXIT_CODE
	fi
fi

if ! [ -z ${MGMT_HTTPS_PORT} ]; then
	if [ $MGMT_HTTPS_PORT -gt 0 ] && [ $MGMT_HTTPS_PORT -lt 65535 ]; then
		echo "Applying ${MGMT_HTTPS_PORT} as management https port"
		echo "set nsparam -mgmthttpsport" $MGMT_HTTPS_PORT >> $BOOTUP_CONF
		HTTPS_PORT=$MGMT_HTTPS_PORT
	else
		echo "MGMT_HTTPS_PORT is not in the range of 0 to 65535"
		exit $FAILURE_EXIT_CODE
	fi
fi

# Change Listen port to run httpd on HTTP_PORT(default is 9080) in side-car poxy mode.
# In side-car proxy mode, application and cpx run in same network namespace,
# and port 80 is often used by web applications, so it is required to keep it free.
# If MGMT_HTTP_PORT is not defined, define it and set it to default value of 9080.
if [ $_CPX_SIDECAR_MODE == 1 ]; then
        if [ -z ${MGMT_HTTP_PORT} ] ;
        then
           export MGMT_HTTP_PORT=9080
        fi

	sed -i "s/^Listen 80$/Listen $HTTP_PORT/" /var/netscaler/contrib/httpd/conf/httpd.conf
fi

if [ -n "$HTTPD_START_SERVERS" ]; then
	sed -i "/\<IfModule mpm_prefork_module\>/,/\<\/IfModule\>/s/\(StartServers\).*/StartServers\t\t$HTTPD_START_SERVERS/" /var/netscaler/contrib/httpd/conf/extra/httpd-mpm.conf
	echo "HTTPD_START_SERVERS set" >> $BOOTUP_LOGS
fi

if [ -n "$HTTPD_MIN_SPARE_SERVERS" ]; then
	sed -i "/\<IfModule mpm_prefork_module\>/,/\<\/IfModule\>/s/\(MinSpareServers\).*/MinSpareServers\t\t$HTTPD_MIN_SPARE_SERVERS/" /var/netscaler/contrib/httpd/conf/extra/httpd-mpm.conf
	echo "HTTPD_MIN_SPARE_SERVERS set" >> $BOOTUP_LOGS
fi
if [ $NS_CPX_LITE -eq 1 ]; then
	sed -i "/\<IfModule mime_module\>/,/\<\/IfModule\>/s/AddEncoding x-compress .Z/#AddEncoding x-compress .Z/" /var/netscaler/contrib/httpd/conf/httpd.conf
	sed -i "/\<IfModule mime_module\>/,/\<\/IfModule\>/s/AddEncoding x-gzip .gz .tgz/#AddEncoding x-gzip .gz .tgz/" /var/netscaler/contrib/httpd/conf/httpd.conf
	sed -i "/\<IfModule mime_module\>/,/\<\/IfModule\>/s/AddType application\/x-httpd-php .php/#AddType application\/x-httpd-php .php/" /var/netscaler/contrib/httpd/conf/httpd.conf
	sed -i "/\<IfModule mime_module\>/,/\<\/IfModule\>/s/AddType application\/x-httpd-php-source .phps/#AddType application\/x-httpd-php-source .phps/" /var/netscaler/contrib/httpd/conf/httpd.conf
	sed -i "/\<IfModule mime_module\>/,/\<\/IfModule\>/s/PHPIniDir \/var\/netscaler\/contrib\/httpd\/lib\//#PHPIniDir \/var\/netscaler\/contrib\/httpd\/lib\//" /var/netscaler/contrib/httpd/conf/httpd.conf
	sed -i "/\<IfModule mime_module\>/,/\<\/IfModule\>/s/#AddType application\/x-compress .Z/AddType application\/x-compress .Z/" /var/netscaler/contrib/httpd/conf/httpd.conf
	sed -i "/\<IfModule mime_module\>/,/\<\/IfModule\>/s/#AddType application\/x-gzip .gz/AddType application\/x-gzip .gz/" /var/netscaler/contrib/httpd/conf/httpd.conf

    #In case of LWCPX, use direct nitro requests to C extension, instead of php
    sed -i '/#LoadModule nsapi_module modules\/mod_nsapi.so/c\LoadModule nsapi_module modules\/mod_nsapi.so' /var/netscaler/contrib/httpd/conf/httpd.conf
	sed -i '/#<LocationMatch ^\/nitro>/c\<LocationMatch ^\/nitro>' /var/netscaler/contrib/httpd/conf/httpd.conf
	sed -i '/#.*SetHandler nitro-handler/c\\tSetHandler nitro-handler' /var/netscaler/contrib/httpd/conf/httpd.conf
	sed -i '/#<\/LocationMatch>/c\\<\/LocationMatch\>' /var/netscaler/contrib/httpd/conf/httpd.conf
    sed -i '/httpd_cpx_ext.conf/d' /var/netscaler/contrib/httpd/conf/httpd.conf
fi
($NETNS /var/netscaler/contrib/httpd/bin/httpd -k start -f /var/netscaler/contrib/httpd/conf/httpd.conf &) 2>> $BOOTUP_LOGS

{
	$NETNS ifconfig $ns1dev
} &> /dev/null
if [ $? -ne 0 ]; then
	non_privileged_mode_handler "Please use this option with docker run command: --cap-add=NET_ADMIN"
fi

#Creating libnsdpdk soft-link from stub lib
if [ ! -L /var/netscaler/lib32/std32/libnsdpdk.so ]; then
	ln -sf /var/netscaler/lib32/std32/libnsdpdk-stub.so /var/netscaler/lib32/std32/libnsdpdk.so
fi

cd $BIN
$NETNS $BIN/nsppe $CPX_CORES

# Generate CPX UUID and Random ID if not present 
# Generated files are present under DEVICEINFO_DIR and has to soft-linked to /var/
if [ ! -d $DEVICEINFO_DIR ]; then
	mkdir -p $DEVICEINFO_DIR
fi
python /var/netscaler/bins/generate_cpx_uuid.py
if [ ! -e $FILE_DEVICE_ID ]; then
	ln -sf $DEVICEINFO_DIR/device_id $FILE_DEVICE_ID
fi
if [ ! -e $FILE_RANDOM_ID ]; then
	ln -sf $DEVICEINFO_DIR/random_id $FILE_RANDOM_ID
fi

#Create ssl certificates
create_default_certificate
create_sftrust_certificate

if [ $NO_SYNC -ne 1 ]
then
# Adding nsfsyncd to crontab for triggering it every min
if [ -f /etc/crontab ]; then
    ret=$(grep -c "nsfsyncd" /etc/crontab)
	if [[ $ret -eq 0 ]]; then
	    sed -i "/# m h dom /a * * * * * root /var/netscaler/bins/nsfsyncd -p" /etc/crontab
	fi
	out=$(grep "minsize" /etc/logrotate.d/rsyslog)
	if [ $? -eq 1 ]; then
		sed -i -e "s/daily/daily\\n\\tminsize 200K/" /etc/logrotate.d/rsyslog
	fi
	/bin/sh /netscaler/nslog.sh start
	if [ $REDHAT -eq 1 ]; then
		$NETNS /usr/sbin/crond
	else
		$NETNS /usr/sbin/cron
	fi
	if [[ $? -ne 0 ]]; then
		echo "warning: cron daemon failed to start. Periodic file sync might not work in HA mode."
	fi
fi
else
	echo "cron is not started in lightweight cpx" >> $BOOTUP_LOGS
	sed -i '/cron/c\ ' /var/netscaler/conf/cpx_monitrc
fi

#$1 is the process and its arguments, where as $2 is equal to "1" when the process is not getting daemonized
start_service()
{
	$NETNS $BIN/ns_service_start "$1" "$2"
	ret_code=$?
	if ! [ $ret_code -eq 0 ]; then
		echo service[$1] start failed with return code $ret_code
		echo "Exiting CPX"
		exit $ret_code
	fi
}


start_service "nsaggregatord -i $LOOPIP"
$NETNS $BIN/nssetup -f
# Introducing sleep here because PE takes time to initialize completely after it daemonizes. 
# We were getting PE is in wrong state to receive the command.
# This sleep will make sure that PE is initialized completely when nsnetsvc/nsconfigd 
sleep 5
start_service nslped
start_service "nsnetsvc -S"

if [ $NO_NSMAP -ne 1 ]
then
	#creating folders used by nsmap service  and starting nsmap service
	mkdir  -p /var/netscaler/locdb/
	mkdir  -p /var/netscaler/inbuilt_db
	start_service "nsmap -l"
else
	echo "nsmap not started in lightweight cpx" >> $BOOTUP_LOGS
	sed -i '/"nsmap/c\ ' /var/netscaler/conf/cpx_monitrc
fi

sleep 2

start_service "nsconfigd -S"

if [ $NO_DATADAEMON_NSCOLLECT -ne 1 ]; then
        #Creating /var/log/db for nscollect and datadaemon to collect various data
        mkdir -p /var/log/db
        # Starting nscollect and datadaemon here as these don't need monitoring.
        $NETNS $BIN/nscollect start &
        $NETNS $BIN/nscollect aggmode &
        $NETNS $BIN/datadaemon
fi

if [ $NO_NSTRACEAGGREGATOR -ne 1 ]; then
	start_service nstraceaggregator
else
	sed -i '/nstraceaggregator/c\ ' /var/netscaler/conf/cpx_monitrc 
    echo "nstraceaggregator not started in lightweight cpx" >> $BOOTUP_LOGS
fi

if [ $NO_SNMPD -ne 1 ]; then
	start_service snmpd
else
	sed -i '/snmpd/c\ ' /var/netscaler/conf/cpx_monitrc 
	echo "snmpd not started in lightweight cpx" >> $BOOTUP_LOGS
fi

if [ $NO_IMI -ne 1 ]; then
	start_service "imi -d"
else
	echo "imi is not started in lightweight cpx" >> $BOOTUP_LOGS
	sed -i '/imi/c\ ' /var/netscaler/conf/cpx_monitrc
fi

if [ $NO_ASLEARN -ne 1 ]; then
	start_service "aslearn -start -f /var/netscaler/conf/aslearn.linux.conf" "1"
else
	echo "aslearn not started in lightweight cpx" >> $BOOTUP_LOGS
	sed -i '/aslearn/c\ ' /var/netscaler/conf/cpx_monitrc
fi

if [ $NO_SYNC -ne 1 ]
then
	start_service "nsfsyncd -d"
	$NETNS /bin/bash /var/netscaler/bins/nssync.sh start &
	$NETNS $BIN/rsync --daemon --config=/var/netscaler/conf/rsyncd.conf
else
	echo "nsfsyncd & rsync  not started in lightweight cpx" >> $BOOTUP_LOGS
	sed -i '/nsfsyncd/c\ ' /var/netscaler/conf/cpx_monitrc
	sed -i '/rsync/c\ ' /var/netscaler/conf/cpx_monitrc
fi

#Configuring nsppe
if [ "$NS_NETMODE" == "HOST" ]; then
	DEF_ROUTE=$NS_GATEWAY
fi
#Add All static MAC
count_ip=${#stat_ip[@]}
for ((i=0;i<$count_ip;++i)); do
        echo "add arp -ipAddress " ${stat_ip[i]} " -mac " ${stat_mac[i]} " -ifnum 0/2" >> $ROUTE_ARP_CONF
done
#Add all Host routes
count_host_route=${#host_route[@]}
for ((i=0;i<$count_host_route;++i)); do
		echo "add route " ${host_route[i]} $NSIP_MASK " -vlan 1" >> $ROUTE_ARP_CONF
done

count_intf_gw_route=${#intf_gw_route[@]}
for ((i=0;i<$count_intf_gw_route;++i)); do
        dest=$(echo ${intf_gw_route[i]} | cut -d '/' -f1)
        mask=${cidrtomask[$(echo ${intf_gw_route[i]} | cut -d '/' -f2)]}
        echo "add route $dest $mask -vlan 1" >> $ROUTE_ARP_CONF
done

if [ "$DEF_ROUTE" ]; then
    echo "add route 0 0 " $DEF_ROUTE >> $ROUTE_ARP_CONF
fi

# Adding the static routes in CPX  stored in IPGW_ROUTE
for i in $(echo $IPGW_ROUTE)
do
    NETWORK=$(echo $i | cut -d '/' -f1)
    CIDR=$(echo $i | cut -d '/' -f2 | cut -d '-' -f1)
    GW=$(echo $i | cut -d '-' -f2)
    NETMASK=${cidrtomask[$CIDR]}
    echo "add route $NETWORK  $NETMASK $GW" >> $ROUTE_ARP_CONF
done

# If case handles the case of pod restart in K8s environment
# If it's a restart, thenm CPX_RESTART_CONF file should have prior route/arp config 
# else, all route and arp configurations will be pushed to BOOTUP_CONF
if [[ -v KUBERNETES_SERVICE_HOST ]] && [ -s $CPX_RESTART_CONF ]; then
   cat $CPX_RESTART_CONF >> $BOOTUP_CONF
else
   cat $ROUTE_ARP_CONF >> $BOOTUP_CONF
fi

# Used for 'add_nameserver'
def_dns_prefix="cpx_default_dns_"
servicegroup=$def_dns_prefix"servicegroup"
vserver=$def_dns_prefix"vserver"
servicegroup_tcp=$def_dns_prefix"tcp_servicegroup"
vserver_tcp=$def_dns_prefix"tcp_vserver"
monitor_tcp=$def_dns_prefix"tcp_monitor"

# To add DNS nameserver(s) from /etc/resolv.conf
function add_nameserver()
{
	echo "add servicegroup $servicegroup dns" >> $BOOTUP_CONF
	echo "add servicegroup $servicegroup_tcp dns_tcp" >> $BOOTUP_CONF
	echo "add monitor $monitor_tcp tcp" >> $BOOTUP_CONF
	# According to RFC 5966, TCP support is a must. Based on this,
	# we bind TCP monitor to the DNS service group (UDP based) as well.
	echo "bind servicegroup $servicegroup -monitorName $monitor_tcp" >> $BOOTUP_CONF
	echo "bind servicegroup $servicegroup_tcp -monitorName $monitor_tcp" >> $BOOTUP_CONF

	echo "add lb vserver $vserver dns" >> $BOOTUP_CONF
	echo "add lb vserver $vserver_tcp dns_tcp" >> $BOOTUP_CONF
	echo "bind lb vserver $vserver $servicegroup" >> $BOOTUP_CONF
	echo "bind lb vserver $vserver_tcp $servicegroup_tcp" >> $BOOTUP_CONF

	# Iterate through all the nameservers, add them as servers and bind to servicegroup
	cat /etc/resolv.conf | grep nameserver | grep -v '^#' | awk '{print $2}' | while read -r nameserver; do
		echo "Adding $nameserver as a nameserver" >> $BOOTUP_LOGS
		echo "bind servicegroup $servicegroup $nameserver 53" >> $BOOTUP_CONF
		echo "bind servicegroup $servicegroup_tcp $nameserver 53" >> $BOOTUP_CONF
	done
	echo "add dns nameserver $vserver" >> $BOOTUP_CONF
	echo "add dns nameserver $vserver_tcp -type TCP" >> $BOOTUP_CONF
}

# To populate the arp and route config for the first iteration on K8s environment
function populate_cpx_restart_config()
{
   if [ ! -d $CPX_RESTART_CONF_DIR ]; then
       echo "ERROR: cpx/conf directory is not present"
   else
       if [ ! -f $CPX_RESTART_CONF ]; then 
           cat $ROUTE_ARP_CONF >> $CPX_RESTART_CONF
       fi
   fi
}

echo "add ssl certkey ns-server-certificate -cert ns-server.cert -key ns-server.key"  >> $BOOTUP_CONF
# Setting up rnat for CPX_SIDECAR_MODE
if [ $_CPX_SIDECAR_MODE == 1 ]; then
	echo "set rnat 192.0.0.0 255.255.255.0 -natip " $NSIP >> $BOOTUP_CONF
fi
#Set the tcp default profile MSS to ns0 MTU to make it work with overlay n/w
if [ $MSS ]
then
	echo "set tcpprofile nstcp_default_profile mss " $MSS >> $BOOTUP_CONF
	echo "set tcpprofile nstcp_internal_apps mss " $MSS >> $BOOTUP_CONF
fi

# Setting the hostname in NSPPE
# If hostname is not provided during container creation, container id
# will be set as hostname in NSPPE and Linux.
# Setting hostname as CPX/cpx results into error at later stage, so
# blocking it here with error message.
if [[ "${HOSTNAME,,}" =~ ^(cpx)$ ]]; then
	echo "Hostname can not be set as" $HOSTNAME
	echo "Exiting CPX"
	exit $FAILURE_EXIT_CODE
fi
echo "set ns hostname" $HOSTNAME >> $BOOTUP_CONF

# Check if DNS_SVC_IP is passed and validate the same for CPX as nodelocal DNS
if [[ -v KUBERNETES_SERVICE_HOST ]] && [ ! -z ${KUBE_DNS_SVC_IP} ]; then
	validate_ipv4 $KUBE_DNS_SVC_IP
	if [ $? -eq 0 ]; then
		# Configure servicegroup and bind kube-dns svcIP to DNS and DNS_TCP servicegroups
		echo "add servicegroup cpx_nodelocal_dns_sg_udp DNS" >> $BOOTUP_CONF
		echo "add servicegroup cpx_nodelocal_dns_sg_tcp DNS_TCP" >> $BOOTUP_CONF
		echo "add monitor cpx_nodelocal_dns_mon_tcp TCP" >> $BOOTUP_CONF
		echo "bind servicegroup cpx_nodelocal_dns_sg_udp $KUBE_DNS_SVC_IP 53" >> $BOOTUP_CONF
		echo "bind servicegroup cpx_nodelocal_dns_sg_tcp $KUBE_DNS_SVC_IP 53" >> $BOOTUP_CONF
		echo "bind servicegroup cpx_nodelocal_dns_sg_udp -monitorname cpx_nodelocal_dns_mon_tcp" >> $BOOTUP_CONF
		echo "bind servicegroup cpx_nodelocal_dns_sg_tcp -monitorname cpx_nodelocal_dns_mon_tcp" >> $BOOTUP_CONF

		# Configure DNS UDP and TCP CS vserver to listen on NSIP
		echo "enable feature cs lb responder" >> $BOOTUP_CONF
		echo "add cs vserver cpx_nodelocal_dns_cs_udp DNS $NSIP 53" >> $BOOTUP_CONF
		echo "add cs vserver cpx_nodelocal_dns_cs_tcp DNS_TCP $NSIP 53" >> $BOOTUP_CONF

		# Configure LB vservers and bind them with servicegroups
		echo "add lb vserver cpx_nodelocal_dns_lb_udp DNS" >> $BOOTUP_CONF
		echo "add lb vserver cpx_nodelocal_dns_lb_tcp DNS_TCP" >> $BOOTUP_CONF
		echo "bind lb vserver cpx_nodelocal_dns_lb_udp cpx_nodelocal_dns_sg_udp" >> $BOOTUP_CONF
		echo "bind lb vserver cpx_nodelocal_dns_lb_tcp cpx_nodelocal_dns_sg_tcp" >> $BOOTUP_CONF

		# Bind CS vservers with default LB vservers
		echo "bind cs vserver cpx_nodelocal_dns_cs_udp -lbvserver cpx_nodelocal_dns_lb_udp" >> $BOOTUP_CONF
		echo "bind cs vserver cpx_nodelocal_dns_cs_tcp -lbvserver cpx_nodelocal_dns_lb_tcp" >> $BOOTUP_CONF

		# Create IP table rule for node-local-dns cache
		if [ ! -z ${CPX_DNS_SVC_IP} ]; then
			validate_ipv4 $CPX_DNS_SVC_IP
			if [ $? -eq 0 ]; then
				echo "Configure iptable rule for $CPX_DNS_SVC_IP" >> $BOOTUP_LOGS
				nsenter --net=/netns/default/net iptables -t nat -I PREROUTING -d $CPX_DNS_SVC_IP -j DNAT --to-destination $NSIP -m comment --comment cpx_nodelocal_dns
			fi
		fi

		# Force DNS query over TCP
		if [ $NS_DNS_FORCE_TCP -eq 1 ]; then
			echo "add responder action cpx_nodelocal_dns_resp_act_set_tc_bit respondwith DNS.NEW_RESPONSE(true, true, NOERROR)" >> $BOOTUP_CONF
			echo "add responder policy cpx_nodelocal_dns_enforce_tcp dns.REQ.TRANSPORT.EQ(udp) cpx_nodelocal_dns_resp_act_set_tc_bit" >> $BOOTUP_CONF
			echo "bind lb vserver cpx_nodelocal_dns_lb_udp -policyName cpx_nodelocal_dns_enforce_tcp -type request -priority 100" >> $BOOTUP_CONF
		fi

		# Check if external nameserver queries are enabled
		if [ ! -z ${NS_DNS_EXT_RESLV_IP} ]; then
			validate_ipv4 $NS_DNS_EXT_RESLV_IP
			if [ $? -eq 0 ]; then
				# Configure LBVS and servicegroup for external nameserver
				echo "add servicegroup cpx_nodelocal_dns_sg_ext_udp DNS" >> $BOOTUP_CONF
				echo "add servicegroup cpx_nodelocal_dns_sg_ext_tcp DNS_TCP" >> $BOOTUP_CONF
				echo "bind servicegroup cpx_nodelocal_dns_sg_ext_udp $NS_DNS_EXT_RESLV_IP 53" >> $BOOTUP_CONF
				echo "bind servicegroup cpx_nodelocal_dns_sg_ext_tcp $NS_DNS_EXT_RESLV_IP 53" >> $BOOTUP_CONF
				echo "bind servicegroup cpx_nodelocal_dns_sg_ext_udp -monitorname cpx_nodelocal_dns_mon_tcp" >> $BOOTUP_CONF
				echo "bind servicegroup cpx_nodelocal_dns_sg_ext_tcp -monitorname cpx_nodelocal_dns_mon_tcp" >> $BOOTUP_CONF

				echo "add lb vserver cpx_nodelocal_dns_lb_ext_udp DNS" >> $BOOTUP_CONF
				echo "add lb vserver cpx_nodelocal_dns_lb_ext_tcp DNS_TCP" >> $BOOTUP_CONF
				echo "bind lb vserver cpx_nodelocal_dns_lb_ext_udp cpx_nodelocal_dns_sg_ext_udp" >> $BOOTUP_CONF
				echo "bind lb vserver cpx_nodelocal_dns_lb_ext_tcp cpx_nodelocal_dns_sg_ext_tcp" >> $BOOTUP_CONF

				# Configure CS policy to redirect external queries
				echo "add cs action cpx_nodelocal_dns_act_udp -targetLBVserver cpx_nodelocal_dns_lb_ext_udp" >> $BOOTUP_CONF
				echo "add cs action cpx_nodelocal_dns_act_tcp -targetLBVserver cpx_nodelocal_dns_lb_ext_tcp" >> $BOOTUP_CONF
				echo "add cs policy cpx_nodelocal_dns_ext_udp -rule DNS.REQ.QUESTION.DOMAIN.CONTAINS(\"$NS_DNS_MATCH_DOMAIN\") -action cpx_nodelocal_dns_act_udp" >> $BOOTUP_CONF
				echo "add cs policy cpx_nodelocal_dns_ext_tcp -rule DNS.REQ.QUESTION.DOMAIN.CONTAINS(\"$NS_DNS_MATCH_DOMAIN\") -action cpx_nodelocal_dns_act_tcp" >> $BOOTUP_CONF
				echo "bind cs vserver cpx_nodelocal_dns_cs_udp -policyname cpx_nodelocal_dns_ext_udp -priority 10" >> $BOOTUP_CONF
				echo "bind cs vserver cpx_nodelocal_dns_cs_tcp -policyname cpx_nodelocal_dns_ext_tcp -priority 10" >> $BOOTUP_CONF

				# Force DNS query over TCP
				if [ $NS_DNS_FORCE_TCP -eq 1 ]; then
					echo "bind lb vserver cpx_nodelocal_dns_lb_ext_udp -policyName cpx_nodelocal_dns_enforce_tcp -type request -priority 100" >> $BOOTUP_CONF
				fi
			fi
		fi
	fi
fi

if [ $NS_CPX_LITE -eq 1 ]; then
	# Set the monitor connection close parameter to RESET for LWCPX
	echo "set lb parameter -monitorConnectionClose RESET" >> $BOOTUP_CONF
fi

# Temporary AppFw bypass rules for CPX. Once Linux apps start generating
# traffic using NSIP, these rules can be removed from here.
echo "add appfw policy cpx_import_bypadd \"client.ip.src.eq(192.0.0.2)\" APPFW_BYPASS" >> $BOOTUP_CONF
echo "bind appfw global cpx_import_bypadd 1 END -type REQ_OVERRIDE" >> $BOOTUP_CONF

#NSNET-7267: AppFlow Configuration addition in CPX using ENV variable
if [[ -v LOGPROXY ]] || [[ -v LOGSTREAM_COLLECTOR_IP ]]; then
	#If log Proxy env is set, use IP from getent command as collector ip, else use it from LOGSTREAM_COLLECTOR_IP env variable passed
	if [[ -v LOGPROXY ]]; then
		if [[ "$LOGPROXY" = "HOST" ]]
		then
			LOGPROXY=$HOSTNAME
		fi
		LOGSTREAM_COLLECTOR_IP=$(getent ahostsv4 $LOGPROXY | grep STREAM | awk 'NR == 1{print $1}')
	fi

	#enable ULFD mode
	echo "en ns mode ulfd" >> $BOOTUP_CONF
	#Enable AppFlow feature
	echo "en ns feature appflow" >> $BOOTUP_CONF
	#Add logstream collector on Specific IP and Port
	echo "add appflow collector logproxy_lstreamd -IPAddress $LOGSTREAM_COLLECTOR_IP -port $APPFLOW_LOG_PORT -Transport logstream" >> $BOOTUP_CONF
	#Set appflow parameters
	echo "set appflow param -templateRefresh 3600 -httpUrl ENABLED -httpCookie ENABLED -httpReferer ENABLED -httpMethod ENABLED -httpHost ENABLED -httpUserAgent ENABLED -httpContentType ENABLED -httpAuthorization ENABLED -httpVia ENABLED -httpXForwardedFor ENABLED -httpLocation ENABLED -httpSetCookie ENABLED -httpSetCookie2 ENABLED -httpDomain ENABLED -httpQueryWithUrl ENABLED -metrics ENABLED -events ENABLED -auditlogs ENABLED" >> $BOOTUP_CONF
	#Add AppFlow Action for added collector
	echo "add appflow action logproxy_lstreamd -collectors logproxy_lstreamd" >> $BOOTUP_CONF
	#Add AppFlow policy for added collector
	echo "add appflow policy logproxy_policy true logproxy_lstreamd" >> $BOOTUP_CONF
	#Bind AppFlow policy
	echo "bind appflow global logproxy_policy 10 END -type REQ_DEFAULT" >> $BOOTUP_CONF
	# NSBASE-9121: Service graph TCP support
	echo "bind appflow global logproxy_policy 10 END -type OTHERTCP_REQ_DEFAULT" >> $BOOTUP_CONF
fi


if [[ -v REST_COLLECTOR_IP ]]; then
	echo "en ns feature appflow" >> $BOOTUP_CONF
	#Add REST collector on specific port and IP
	echo "add appflow collector cpx_rest_collector -IPAddress $REST_COLLECTOR_IP -port $APPFLOW_REST_PORT -Transport rest" >> $BOOTUP_CONF
fi

# NSBASE-8582: Get the DNS nameserver from /etc/resolv.conf and add it to NS config
if [ -z ${KUBE_DNS_SVC_IP} ]; then
	add_nameserver
fi

$NETNS $BIN/cli_script.sh "set system user nsroot -password $(cat $FILE_RANDOM_ID)" ":nsroot:nsroot" &> /dev/null
echo "Updated non-default password for nsroot" >> $BOOTUP_LOGS
echo -e "$(cat $FILE_RANDOM_ID)\n$(cat $FILE_RANDOM_ID)" | passwd nsroot
echo -e "$(cat $FILE_RANDOM_ID)\n$(cat $FILE_RANDOM_ID)" | passwd root
echo "Updated non-default password for ssh login for users nsroot, root" >> $BOOTUP_LOGS
$NETNS $BIN/cli_script.sh $BOOTUP_CONF >> $BOOTUP_LOGS

# added to fix WEBUI permissions and show nsroot password
echo "Fixing WEBGUI permissions.."
chmod 777 /var/nstmp
echo "nsroot password is: $(cat /var/deviceinfo/random_id)"
# custom section end

if [[ -v KUBERNETES_SERVICE_HOST ]]; then
   populate_cpx_restart_config
fi

# Call cpx registration
# Assumes that the following environment variables are set, if they
# have non default values. Please refer to cpx_registration for default
# values:
# 'NS_IP',
# 'NS_HTTP_PORT',
# 'NS_HTTPS_PORT' ,
# 'NS_SSH_PORT',
# 'NS_SNMP_PORT',
# 'NS_ROUTABLE',
# 'MESOS_TASK_ID',
# 'NS_MGMT_SERVER',
# 'NS_MGMT_PRE_AUTH_KEY'
# 'NS_MGMT_DEPLOYMENT_MODE'

# Determining access ports
# In non-routable case access ports for HTTP, HTTPS, SNMP, SSH
# need to be defined.
# If NS_<Service>_PORT is defined, use it as this is explicitly given by user
# In Mesos/Marathon environment, in bridge mode, exposed ports are given by container number:
# PORT_80, PORT_443, PORT_161, PORT_22, variables will have exposed port number
# In routable case use default ports

if [ "$NS_NETMODE" == "IP_PER_CONTAINER" ]; then
	NS_ROUTABLE="TRUE"
else
	NS_ROUTABLE="FALSE"
fi

if [ `echo $NS_ROUTABLE | tr [a-z] [A-Z]` = "FALSE" ]
then
    if ! [[ -v NS_HTTP_PORT ]]
    then
        if [[ -v PORT_80 ]]
        then
            export NS_HTTP_PORT=$PORT_80
        else
            export NS_HTTP_PORT=9995
        fi
    else
        export NS_HTTP_PORT=$NS_HTTP_PORT
    fi
    if ! [[ -v NS_HTTPS_PORT ]]
    then
        if [[ -v PORT_443 ]]
        then
            export NS_HTTPS_PORT=$PORT_443
        else
            export NS_HTTPS_PORT=9996
        fi
    else
        export NS_HTTPS_PORT=$NS_HTTPS_PORT
    fi
    if ! [[ -v NS_SNMP_PORT ]]
    then
        if [[ -v PORT_161 ]]
        then
            export NS_SNMP_PORT=$PORT_161
        else
            export NS_SNMP_PORT=9998
        fi
    else
        export NS_SNMP_PORT=$NS_SNMP_PORT
    fi
    if ! [[ -v NS_SSH_PORT ]]
    then
        if [[ -v PORT_22 ]]
        then
            export NS_SSH_PORT=$PORT_22
        else
            export NS_SSH_PORT=9997
        fi
    else
        export NS_SSH_PORT=$NS_SSH_PORT
    fi
fi

if [ $NS_CPX_LITE -eq 1 ]; then
    export  INSTANCE_CLASSIFIER=1
    echo "Lightweight CPX Instance" >> $BOOTUP_LOGS
 else
    export INSTANCE_CLASSIFIER=0
    echo "Regular CPX Instance" >> $BOOTUP_LOGS
 fi

if [[ -v NS_LB_ROLE ]]
then
	NS_LB_ROLE=`echo $NS_LB_ROLE | tr [A-Z] [a-z]`
	if [ $NS_LB_ROLE != "client" -a $NS_LB_ROLE != "server" ]
	then
		echo "Unknown lb role $NS_LB_ROLE. Defaulting to server..." >> $BOOTUP_LOGS
		NS_LB_ROLE="server"
	fi
else
	NS_LB_ROLE="server"
fi

export NS_LB_ROLE=$NS_LB_ROLE

# Marathon provides HOST variable
# Kubernetes provides HOSTNAME variable
# CPX registration looks for the HOST varaible, so need to transform other forms to the HOST variable. 
if ! [[ -v HOST ]]
then
	if [[ -v HOSTNAME ]]
	then
	# Kubernetes provides HOSTNAME variable in the container equal to `hostname` on the host 
		export HOST=$HOSTNAME
	fi
fi

CPX_REGISTRATION_EXIT_STATUS=0
export NSIP=$NSIP

if [[ -v MESOS_TASK_ID ]]
then
	export ORCHESTRATION_TASK_ID=$MESOS_TASK_ID
elif [[ -v KUBERNETES_TASK_ID ]]
then
	export ORCHESTRATION_TASK_ID=$KUBERNETES_TASK_ID
else
	export ORCHESTRATION_TASK_ID=""
fi

cpx_registration "register" 2>>$BOOTUP_LOGS

# If CPX registration is unsuccessful, CPX_REGISTRATION_EXIT_STATUS set it to 1.
if [[ $? -ne 0 ]]; then
	CPX_REGISTRATION_EXIT_STATUS=1
fi

echo "error is $CPX_REGISTRATION_EXIT_STATUS" 1>>$BOOTUP_LOGS

if [[ $CPX_REGISTRATION_EXIT_STATUS != 0 ]]; then
    echo "Registration failed, will honor NS_ABORT_ON_FAILED_REGISTRATION" 1>>$BOOTUP_LOGS
    if [[ -v NS_ABORT_ON_FAILED_REGISTRATION ]]; then
        if [[ `echo $NS_ABORT_ON_FAILED_REGISTRATION | tr [:upper:] [:lower:]` = "true" ]]; then
            echo "ERROR: Registration error: Aborting on failed registration."
            exit 0
        fi
    fi
fi
if [[ $CPX_REGISTRATION_EXIT_STATUS == 0 ]]; then
    REG_ERROR=''
    if [[ -v NS_MGMT_SERVER ]]; then
        REG_ERROR=$($NETNS $BIN/cli_script.sh "add centralmanagementserver ONPREM nsroot nsroot -serverName $NS_MGMT_SERVER")
        if [[ `grep -c -i "ERROR:" <<< $REG_ERROR` != 0 ]]; then
            REG_ERROR=$($NETNS $BIN/cli_script.sh "add centralmanagementserver ONPREM nsroot nsroot -IPAddress $NS_MGMT_SERVER")
            if [[ `grep -c -i "ERROR:" <<< $REG_ERROR` != 0 ]]; then
                if [[ -v NS_ABORT_ON_FAILED_REGISTRATION ]]; then
                    if [[ `echo $NS_ABORT_ON_FAILED_REGISTRATION | tr [:upper:] [:lower:]` = "true" ]]; then
                        echo "ERROR: Registration error: Aborting on failed registration."
                        exit 0
                    fi
                fi
            fi
        fi
    fi
fi
# CPX generates its own UUID. Set UUID in PE using set ns config -deviceid command
# Read UUID from /var/device_id file
if [[ -e $FILE_DEVICE_ID ]] ; then
CPX_UUID="`cat $FILE_DEVICE_ID`"
echo $CPX_UUID
$NETNS $BIN/cli_script.sh "set ns config -deviceid $CPX_UUID"
else
echo "$FILE_DEVICE_ID not found!"
fi

# Ports for HA communication
NS_HA_PORT=3003
NS_CONFIG_PORT=3010
NS_RSYNC_PORT=8873

cpx_add_iptables_rules()
{
   IPTN="iptables -t nat"
   NSHOST="CPX-NODEPORT"
   NSOUTPUT="CPX-MASQUERADE"
   NSLOOPBACK="CPX-LOOPBACK"
   echo "Creating IP Tables rules for the CPX access" >> $BOOTUP_LOGS

# Creating NetScaler management chain to keep management rules
   echo "Creating $NSHOST chain..." >> $BOOTUP_LOGS
   $IPTN -N $NSHOST

# Creating management rules in to the NetScaler management chain
   echo "Creating $NSHOST chain rules:" >> $BOOTUP_LOGS
   echo "    TCP $NS_HTTP_PORT -> $1:$HTTP_PORT:" >> $BOOTUP_LOGS
   $IPTN -A $NSHOST -p tcp --dport $NS_HTTP_PORT -j DNAT --to-destination $1:$HTTP_PORT
   echo "    TCP $NS_HTTPS_PORT -> $1:$HTTPS_PORT:" >> $BOOTUP_LOGS
   $IPTN -A $NSHOST -p tcp --dport $NS_HTTPS_PORT -j DNAT --to-destination $1:$HTTPS_PORT
   echo "    TCP $NS_SSH_PORT -> $1:22:" >> $BOOTUP_LOGS
   $IPTN -A $NSHOST -p tcp --dport $NS_SSH_PORT -j DNAT --to-destination $1:22
   echo "    UDP $NS_SNMP_PORT -> $1:161:" >> $BOOTUP_LOGS
   $IPTN -A $NSHOST -p udp --dport $NS_SNMP_PORT -j DNAT --to-destination $1:161

# Creating rules for HA communication between CPX host nodes on two
# different docker hosts with no dedicated interface.
   echo "    UDP $NS_HA_PORT -> $1:$NS_HA_PORT:" >> $BOOTUP_LOGS
   $IPTN -A $NSHOST -p udp --dport $NS_HA_PORT -j DNAT --to-destination $1:$NS_HA_PORT
   echo "    TCP $NS_CONFIG_PORT -> $1:$NS_CONFIG_PORT:" >> $BOOTUP_LOGS
   $IPTN -A $NSHOST -p tcp --dport $NS_CONFIG_PORT -j DNAT --to-destination $1:$NS_CONFIG_PORT
   echo "    TCP $NS_RSYNC_PORT -> $1:$NS_RSYNC_PORT:" >> $BOOTUP_LOGS
   $IPTN -A $NSHOST -p tcp --dport $NS_RSYNC_PORT -j DNAT --to-destination $1:$NS_RSYNC_PORT


# Adding NetScaler management chain into PREROUTING chain for all LOCAL destination ip addresses
   echo "Adding $NSHOST chain into PPREROUTING chain..." >> $BOOTUP_LOGS
   $IPTN -I PREROUTING -m addrtype --dst-type LOCAL -m comment --comment "Rules for Steering NodePort traffic to CPX" -j $NSHOST

# Adding NetScaler management rule in to OUTPUT chain for local management access via host ip
   echo "Adding $NSHOST chain into OUTPUT chain..." >> $BOOTUP_LOGS
   $IPTN -I OUTPUT -m addrtype --dst-type LOCAL -m comment --comment "Rules for Steering NodePort traffic to CPX" -j $NSHOST

# Creating NetScaler CPX output rule
   echo "Creating $NSOUTPUT chain..." >> $BOOTUP_LOGS
   $IPTN -N $NSOUTPUT

# Adding rule(s) in to the NetScaler output chain
   echo "Creating $NSOUTPUT chain rules:" >> $BOOTUP_LOGS
   echo "    $1/$2 Masquerade" >> $BOOTUP_LOGS
   $IPTN -A $NSOUTPUT -s $1/$2 -j MASQUERADE

# Adding NetScaler CPX output rule into the POSTROUTING chain
   echo "Adding $NSOUTPUT chain into POSTROUTING chain..." >> $BOOTUP_LOGS
   $IPTN -A POSTROUTING -m comment --comment "Rule for Masquerading CPX originated traffic" -j $NSOUTPUT

# Adding forward rules for CPX interface vethcpx0. This will avoid
# packets being dropped due to FORWARD DROP rule in certain OS versions
# on HOST.
	iptables -I FORWARD -o vethcpx0 -j ACCEPT
	iptables -I FORWARD -i vethcpx0 ! -o vethcpx0 -j ACCEPT

# Creating Loopback rules if required
if [ x$LOOPBACKDISABLED = "x" ]
   then
      LOOPBACKDISABLED="False"
   fi

   if [ $LOOPBACKDISABLED = "False" ]
   then
      echo "Issuing sysctl command to allow localhost routing..." >> $BOOTUP_LOGS
      sysctl -w net.ipv4.conf.all.route_localnet=1
      echo "Creating $NSLOOPBACK chain:" >> $BOOTUP_LOGS
      $IPTN -N $NSLOOPBACK
      echo "Creating $NSLOOPBACK chain rules:" >> $BOOTUP_LOGS
      echo "    $1/$2 Masquerade" >> $BOOTUP_LOGS
      $IPTN -A $NSLOOPBACK -d $1/$2 -j MASQUERADE
      echo "Adding $NSLOOPBACK chain into POSTROUTING chain..." >> $BOOTUP_LOGS
      $IPTN -A POSTROUTING -s 127.0.0.0/8 -m comment --comment "Rules for MASQUERADING loopback based application traffic to CPX." -j $NSLOOPBACK
   fi
}

cpx_delete_iptables_rules()
{
   IPTN="iptables -t nat"
   NSHOST="CPX-NODEPORT"
   NSOUTPUT="CPX-MASQUERADE"
   NSLOOPBACK="CPX-LOOPBACK"

# Flushing NetSscaler management chain
   echo "Flushing $NSHOST chain..." >> $BOOTUP_LOGS
   $IPTN -F $NSHOST

# Removing NetScaler management rule from PREROUTING
   echo "Removing $NSHOST chain from PREROUTING chain..." >> $BOOTUP_LOGS
   $IPTN -D PREROUTING -m addrtype --dst-type LOCAL -m comment --comment "Rules for Steering NodePort traffic to CPX" -j $NSHOST

# Removing NetScaler management rule from OUTPUT chain
   echo "Removing $NSHOST chain from OUTPUT chain..." >> $BOOTUP_LOGS
   $IPTN -D OUTPUT -m addrtype --dst-type LOCAL -m comment --comment "Rules for Steering NodePort traffic to CPX" -j $NSHOST

# Deleteing netScaler NetScaler CPX management chain
   echo "Deleteing $NSHOST chain..." >> $BOOTUP_LOGS
   $IPTN -X $NSHOST

# Flushing NetSscaler output chain
   echo "Flushing $NSOUTPUT chain..." >> $BOOTUP_LOGS
   $IPTN -F $NSOUTPUT

# Removing NetScaler output rule from POSTROUTING
   echo "Removing $NSOUTPUT chain from POSTROUTING chain..." >> $BOOTUP_LOGS
   $IPTN -D POSTROUTING -m comment --comment "Rule for Masquerading CPX originated traffic" -j $NSOUTPUT

# Deleteing netScaler NetScaler CPX management chain
   echo "Deleteing $NSOUTPUT chain..." >> $BOOTUP_LOGS
   $IPTN -X $NSOUTPUT

# Deleting forward rules for CPX interface vethcpx0.
	iptables -D FORWARD -o vethcpx0 -j ACCEPT
	iptables -D FORWARD -i vethcpx0 ! -o vethcpx0 -j ACCEPT

# Deleting Loopback chain
   echo "Flushing $NSLOOPBACK chain..." >> $BOOTUP_LOGS
   $IPTN -F $NSLOOPBACK

# Removing LOOPBACK rule from POSTROUTING chain
   echo "Removing $NSLOOPBACK chain from POSTROUTING chain..." >> $BOOTUP_LOGS
   $IPTN -D POSTROUTING -s 127.0.0.0/8 -m comment --comment "Rules for MASQUERADING loopback based application traffic to CPX." -j $NSLOOPBACK

# Deleting Lookback chain
   echo "Deleteing $NSLOOPBACK chain..." >> $BOOTUP_LOGS
   $IPTN -X $NSLOOPBACK
}


if   [ -z ${NS_USER} ]; then
	NS_USER=nsroot
fi

if   [ -z ${NS_PASSWORD} ]; then
	NS_PASSWORD=nsroot
fi
function init_kubernetes()
{
        NS_NETMODE=$1
		NS_LB_ROLE=$2
        kubernetes_url=$3
        NS_IP=$4
        NS_PORT=$5
        cpx_triton_log_file=$6
        
        #User should provide LOGLEVEL as environment variable. Default is DEBUG
        LOGLEVEL=${LOGLEVEL:-"DEBUG"}

        #Triton log file location
	if [[ -v NS_TRITON_LOG_FILE ]]
	then
                NS_LOG_FILE_LOC="--logfilename $NS_TRITON_LOG_FILE" 
        else
            NS_LOG_FILE_LOC=""
	fi 

        if [[ -v kubernetes_url ]]; then
            KUBE_SERVER="--kube-apiserver $kubernetes_url"
        else
            KUBE_SERVER=""
        fi
        if [[ -v kube_config ]]; then
            KUBE_CONFIG="--kube-config $kube_config"
        else
            KUBE_CONFIG=""
        fi
        if [[ -v KUBERNETES_TASK_ID ]]; then
                CONFIG_INTERFACE="--config-interface=iptablesmanager"
        else
                CONFIG_INTERFACE="--config-interface=netscaler"
        fi
            NS_IP=$NS_IP NS_PORT=$NS_PORT NS_IP_RANGE=$NS_IP_RANGE \
            NS_NETMODE=$NS_NETMODE NS_LB_ROLE=$NS_LB_ROLE NS_MGMT_SERVER=$NS_MGMT_SERVER \
            NS_USER=$NS_USER NS_PASSWORD=$NS_PASSWORD \
            python /var/netscaler/triton/nstriton.py $CONFIG_INTERFACE $KUBE_SERVER $KUBE_CONFIG \
              --loglevel=$LOGLEVEL  $NS_LOG_FILE_LOC $CMD_LINE_ARGS &
	    TRITON="NS_IP=$NS_IP NS_PORT=$NS_PORT NS_IP_RANGE=$NS_IP_RANGE \
           NS_NETMODE=$NS_NETMODE NS_LB_ROLE=$NS_LB_ROLE NS_MGMT_SERVER=$NS_MGMT_SERVER \
           NS_USER=$NS_USER NS_PASSWORD=$NS_PASSWORD \
           python /var/netscaler/triton/nstriton.py $CONFIG_INTERFACE $KUBE_SERVER $KUBE_CONFIG \
                  --loglevel=$LOGLEVEL  $NS_LOG_FILE_LOC $CMD_LINE_ARGS"
        echo $! > /var/nslog/triton.pid
       # start_triton.sh is for starting triton 	
	echo -e "#!/bin/bash\n" > /var/netscaler/bins/start_triton.sh
        echo "$TRITON &" >> /var/netscaler/bins/start_triton.sh
        echo 'echo $! > /var/nslog/triton.pid' >> /var/netscaler/bins/start_triton.sh
        chmod +x /var/netscaler/bins/start_triton.sh
	# stop_triton.sh is for stoppting triton 	
        echo -e "#!/bin/bash\n" > /var/netscaler/bins/stop_triton.sh
        echo "/usr/bin/pkill -f nstriton.py" >> /var/netscaler/bins/stop_triton.sh
        chmod +x /var/netscaler/bins/stop_triton.sh
	# following codes are added for monitoring triton process  
	echo -e '
           check file tritonfile with path "/var/netscaler/bins/start_triton.sh"
                if does not exist then exec "/usr/bin/pkill -f nstriton.py"

              check process triton with pidfile /var/nslog/triton.pid
                start program = "/bin/bash /var/netscaler/bins/start_triton.sh"
                stop program = "/bin/bash /var/netscaler/bins/stop_triton.sh"
                if 5 restarts within 100 cycles then stop
                depends on tritonfile' >> /var/netscaler/conf/cpx_monitrc
}

if [ "$NS_NETMODE" == "HOST" ]; then

    cpx_delete_iptables_rules
    cpx_add_iptables_rules $NSIP $DOCKER_MASK
        

	if [[ -v marathon_url ]]; then
		if [[ -v marathon_user && -v marathon_password ]]; then
			LOGIN_INFO="--marathon-user="$marathon_user" --marathon-password="$marathon_password
		else
			LOGIN_INFO=""
		fi
		NS_IP=$NS_IP NS_TYPE=CPX NS_NETMODE=$NS_NETMODE NS_LB_ROLE=$NS_LB_ROLE\
		    NS_USER=$NS_USER NS_PASSWORD=$NS_PASSWORD \
		    python /var/netscaler/triton/nstriton.py --marathon-url=$marathon_url \
		    $LOGIN_INFO --logfilename $cpx_triton_log_file&
		    
  elif [[ -v kubernetes_url ]] || [[ -v kube_config ]]; then
       init_kubernetes $NS_NETMODE $NS_LB_ROLE $kubernetes_url $NS_IP $HTTP_PORT $cpx_triton_log_file
  fi
##Support for ingress triton module in non-host mode CPX
elif [[ -v KUBERNETES_SERVICE_HOST ]] && ! [[ -v KUBERNETES_TASK_ID ]]; then
        ##auto create kubernetes api url in case CPX is running in kubernetes environment
        if ! [[ -v kubernetes_url ]]; then
           kubernetes_url="https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT"
         fi

        init_kubernetes "BRIDGE" $NS_LB_ROLE $kubernetes_url  "127.0.0.1" "80" $cpx_triton_log_file
fi

if [ $NO_NSAAAD -ne 1 ]
then
	$NETNS $BIN/ns_service_start nsaaad "1"
else
	echo "nsaaad not started in lightweight cpx" >> $BOOTUP_LOGS
	sed -i '/nsaaad/c\ ' /var/netscaler/conf/cpx_monitrc
fi
	#this should be the last process to start
if [ $REDHAT -eq 1 ]
then
	cp -f /var/netscaler/conf/cpx_monitrc /etc/monitrc
else
	cp -f /var/netscaler/conf/cpx_monitrc /etc/monit/monitrc
fi

#Modify monitrc to watch for syslog and cron.
#TODO metricscollector is not started in case of rhel based systems.
#It should be enabled once metricscollector binary is compiled
#with dynamic linking of libstdc++ library for rhel based systems.
if [ $NO_MONIT -ne 1 ]; then
	if [ $NO_SSHD -ne 1 ]; then
		TEXT="  check process sshd with pidfile /var/run/sshd.pid"
		TEXT+='\n'
		TEXT+="   start program = \"/usr/sbin/sshd\""
		TEXT+='\n'
		TEXT+='   stop program  = \"/bin/bash -c kill -9 $(cat /var/run/sshd.pid)\"'
		TEXT+='\n\n'
	fi
	if [ $REDHAT -eq 1 ]
	then
		TEXT+="  check process syslogd with pidfile /var/run/syslogd.pid"
		TEXT+='\n'
		TEXT+="   start program = \"/usr/sbin/rsyslogd\""
		TEXT+='\n'
		TEXT+='   stop program  = \"/bin/bash -c kill -9 $(cat /var/run/syslogd.pid)\"'
		TEXT+='\n\n'
		TEXT+="  check process crond with pidfile /var/run/crond.pid"
		TEXT+='\n'
		TEXT+="   start program = \"/usr/sbin/crond\""
		TEXT+='\n'
		TEXT+='   stop program  = \"/bin/bash -c kill -9 $(cat /var/run/crond.pid)\"'
		TEXT+='\n'
		sed -i "/#Monitor all other important process/a $TEXT" /etc/monitrc
	else
		TEXT+="  check process syslogd with pidfile /var/run/rsyslogd.pid"
		TEXT+='\n'
		TEXT+="   start program = \"/usr/sbin/rsyslogd\""
		TEXT+='\n'
		TEXT+='   stop program  = \"/bin/bash -c kill -9 $(cat /var/run/rsyslogd.pid)\"'
		TEXT+='\n\n'
		TEXT+="  check process crond with pidfile /var/run/crond.pid"
		TEXT+='\n'
		TEXT+="   start program = \"/usr/sbin/cron\""
		TEXT+='\n'
		TEXT+='   stop program  = \"/bin/bash -c kill -9 $(cat /var/run/crond.pid)\"'
		TEXT+='\n\n'
		TEXT+="  check process metricscollector with pidfile /var/nslog/metricscollector.pid"
		TEXT+='\n'
		TEXT+="   start program = \"/bin/bash /var/netscaler/bins/ns_service_start 'metricscollector -l 192.0.0.1 -a 192.0.0.2'\""
		TEXT+='\n'
		TEXT+="   stop program  = \"/bin/bash /var/netscaler/bins/ns_service_stop metricscollector\""
		TEXT+='\n'
		sed -i "/#Monitor all other important process/a $TEXT" /etc/monit/monitrc
	fi
fi

#File-based startup config
#In Kubernetes environment, direct mounting of file is not possible
#so creating soft-link /etc/cpx.conf for /cpx/conf/cpx.conf(mounted ConfigMap)
KUBE_CONF_MNT=/cpx/conf/cpx.conf
if [[ -f $KUBE_CONF_MNT ]] && ! [[ -f /etc/cpx.conf ]]; then
	ln -s $KUBE_CONF_MNT /etc/cpx.conf
fi
if [[ -f /etc/cpx.conf ]]; then
	#To enable debugging messages, set this flag as 1 else 0
	export DIAG_FLAG=0
	$NETNS $BIN/bootup_conf.sh /etc/cpx.conf
	unset DIAG_FLAG
fi

{
	if [ $NO_MONIT -ne 1 ]; then
		$NETNS monit -I &
	fi
} >> $BOOTUP_LOGS
sleep 1

## Configure Licensing
LICENSE_CONF=/nsconfig/license.conf
if [ -z ${LS_IP} ]; then
	echo "LS_IP is unset" >> $BOOTUP_LOGS;
else
	if [ -z ${LS_PORT} ]; then
	#echo "LS_PORT is unset";
		echo "add licenseserver " $LS_IP >> $LICENSE_CONF
	else
		echo "add licenseserver " $LS_IP "-port " $LS_PORT >> $LICENSE_CONF
	fi
	if [ -z ${BANDWIDTH} ]; then
		if [ -z ${PLATFORM} ]; then
			echo "set capacity -vcpu -edition Platinum" >> $LICENSE_CONF
		else
			echo "set capacity -platform " $PLATFORM >> $LICENSE_CONF
		fi
	else
		#echo "PLATFORM is unset";
		echo "set capacity -unit Mbps -edition Platinum -bandwidth " $BANDWIDTH >> $LICENSE_CONF
	fi
	$NETNS $BIN/cli_script.sh $LICENSE_CONF >> $BOOTUP_LOGS
	rm $LICENSE_CONF
fi
## License config ends
# unsetting the cidrtomask
unset cidrtomask

# Disable selective probe
if [ $_CPX_DISABLE_PROBE == 1 ]; then
	$NETNS $BIN/nsapimgr -ys selective_probe=1 >> $BOOTUP_LOGS
	echo "Selective Probe is disabled"
fi

echo "CPX started successfully. For logs please refer to" $BOOTUP_LOGS

if [ "$RUN_NGS_BOOTSTRAP" != "1" ]; then
        echo -e "\n Environment variable RUN_NGS_BOOTSTRAP is not set" >> $BOOTUP_LOGS
else
        echo -e "\n Environment variable RUN_NGS_BOOTSTRAP is set\n" >> $BOOTUP_LOGS
	echo sslvpn bootstrap start: `date` >> $BOOTUP_LOGS
	/bin/bash /var/netscaler/bins/ngs/ns_bootstrap_cpx.sh
	echo sslvpn bootstrap end: `date` >> $BOOTUP_LOGS
fi

if [ $NO_MONIT -ne 1 ]; then
	wait $(cat /var/run/monit.pid)
fi

#Call cleanup here
if [ $NSCPX_IS_LW_CPX -ne 1 ]; then
    cleanup
fi

