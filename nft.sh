#!/bin/sh
# version: 20260502.02
# nft.sh service action [ip]
# service settings: [service].conf
# service nft ruleset: [service].nft

# Global configuration defaults for banning subnets and nftables naming
DEFAULT_BAN_IPV4_SUBNET="/32"
DEFAULT_BAN_IPV6_SUBNET="/64"
DEFAULT_BAN_TIMEOUT="10m"
DEFAULT_NFT_SET_BLACK4="black4"
DEFAULT_NFT_SET_BLACK6="black6"
DEFAULT_NFT_SET_SERVICE_PORT="service_port"
DEFAULT_NFT_SET_WHITE4="white4"
DEFAULT_NFT_SET_WHITE6="white6"
DEFAULT_NFT_TABLE_PREFIX="ban-"
DEFAULT_NFT_TABLE_TYPE="inet"
DEFAULT_WHITE4_SUFFIX="-white4.txt"
DEFAULT_WHITE6_SUFFIX="-white6.txt"
# const
FILE_NFT_RULES_SUFFIX=".nft"
FILE_SETTINGS_SUFFIX=".conf"

export PATH=/sbin:/bin:/usr/sbin:/usr/bin

# Print error message to stderr and exit
error() {
	[ ! -z "$*" ] && echo "$*" >&2
	exit 1
}

# Display usage instructions
usage() {
	error "Usage: $0 service start|stop|update|ban|unban|flush|show|list [ip]"
}

# $1 = $2, return 0
# $1 > $2, return 1
# $1 < $2, return 2
compare_version() {
	local v1=$1
	local v2=$2
	awk -v a="$v1" -v b="$v2" 'BEGIN { split(a, arrA, "."); split(b, arrB, "."); max = (length(arrA) > length(arrB)) ? length(arrA) : length(arrB); for (i = 1; i <= max; i++) { numA = arrA[i] + 0; numB = arrB[i] + 0; if (numA > numB) { print ">"; exit 1 } if (numA < numB) { print "<"; exit 2 } } print "="; exit 0 }' > /dev/null
	local result=$?
	echo $result
	return $result
}

check_nft_timeout() {
	[ -z "$1" ] && return 1
	printf "%s\n" "$1" | grep -qE '^([1-9][0-9]*d)?([1-9][0-9]*h)?([1-9][0-9]*m)?([1-9][0-9]*s)?$'
}

check_int_list() {
	[ -z "$1" ] && return 1
	printf "%s\n" "$1" | grep -qE '^ *[1-9][0-9]*( *, *[1-9][0-9]*)* *$'
}

# Adds or deletes an IP address to/from the appropriate nftables set (IPv4/IPv6)
# nft_set_action action ip
nft_set_action() {
	if [ -z "$1" ] || [ -z "$2" ]; then return 1; fi

	local _action="add"
	[ "$1" = "delete" ] && _action="delete"

	local _ip="$2"
	local _set
	local _timeout

	if [ "${_ip#*:}" != "$_ip" ]; then
		_set=$NFT_SET_BLACK6
		[ "${_ip#*/}" = "$_ip" ] && _ip="$_ip$BAN_IPV6_SUBNET"
	else
		_set=$NFT_SET_BLACK4
		[ "${_ip#*/}" = "$_ip" ] && _ip="$_ip$BAN_IPV4_SUBNET"
	fi

	if [ "$_action" = "add" ]; then
		_timeout="timeout $BAN_TIMEOUT"
	fi

	nft $_action element $NFT_TABLE_TYPE $NFT_TABLE $_set "{$_ip $_timeout}"
	[ -n "$DEBUG" ] && echo nft $_action element $NFT_TABLE_TYPE $NFT_TABLE $_set "{$_ip $_timeout}" | logger -t nft.sh
}

# Removes the nftables table associated with the specified service
stop() {
	# nft v1.0.7+ introduced support for the destroy action.
	if [ $_NFT -eq 1 ]; then
		nft destroy table $NFT_TABLE_TYPE $NFT_TABLE
	else
		nft delete table $NFT_TABLE_TYPE $NFT_TABLE
	fi
}

# Updates a set by populating a temporary set first and then swapping it to minimize downtime
# The nft command suffers from slow performance due to hostname resolution.
# do_update_swap set_name temp_suffix file
do_update_swap() {
	if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then return 1; fi
	local _set_name="$1"
	local _set_name_temp="$_set_name$2"
	local _file="$3"
	[ ! -s "$_file" ] && return 0

	local _nproc=$(nproc)
	_nproc=${_nproc:=1}

	nft destroy set $NFT_TABLE_TYPE $NFT_TABLE $_set_name_temp || nft delete set $NFT_TABLE_TYPE $NFT_TABLE $_set_name_temp
	nft -t list set $NFT_TABLE_TYPE $NFT_TABLE $_set_name | sed "s/set $_set_name {/set $_set_name_temp {/" | nft -f -
	grep -Ev '^[[:blank:]]*#|^[[:blank:]]*$' "$_file" | xargs -I % -r -P $_nproc nft add element $NFT_TABLE_TYPE $NFT_TABLE $_set_name_temp '{%}'

	nft list set $NFT_TABLE_TYPE $NFT_TABLE $_set_name_temp | sed -e "1i\flush set $NFT_TABLE_TYPE $NFT_TABLE $_set_name" -e "s/set $_set_name_temp {/set $_set_name {/" | nft -f - >/dev/null 2>&1
	nft destroy set $NFT_TABLE_TYPE $NFT_TABLE $_set_name_temp || nft delete set $NFT_TABLE_TYPE $NFT_TABLE $_set_name_temp
}

# Updates both IPv4 and IPv6 whitelist sets from their respective files
update() {
	local _suffix="-temp"
	do_update_swap "$NFT_SET_WHITE4" "$_suffix" "$_SERVICE$WHITE4_SUFFIX"
	do_update_swap "$NFT_SET_WHITE6" "$_suffix" "$_SERVICE$WHITE6_SUFFIX"
}

# Change directory to where the script is located to handle relative paths
_currdir=$(cd "$(dirname "$0")" && pwd)
cd "$_currdir" || exit 1

[ $# -lt 2 ] && usage

_SERVICE="$1"
[ -z "$_SERVICE" ] && usage

: ${FILE_NFT_RULES:="$_SERVICE$FILE_NFT_RULES_SUFFIX"}

# Load optional variables from the service's .conf file if available
_file_settings="$_SERVICE$FILE_SETTINGS_SUFFIX"
[ -r "$_file_settings" ] && eval $(grep -Ev '^[[:blank:]]*#|^[[:blank:]]*$' "$_file_settings" | sed -e "s/'/'\\\''/g" -e "s/=\(.*\)/='\1'/g")

# Set default values for variables if they weren't defined in the config file
: ${SERVICE_PORT:?"Need to set the SERVICE_PORT variable."}

: ${BAN_IPV4_SUBNET:=$DEFAULT_BAN_IPV4_SUBNET}
: ${BAN_IPV6_SUBNET:=$DEFAULT_BAN_IPV6_SUBNET}
: ${BAN_TIMEOUT:=$DEFAULT_BAN_TIMEOUT}
: ${NFT_SET_BLACK4:=$DEFAULT_NFT_SET_BLACK4}
: ${NFT_SET_BLACK6:=$DEFAULT_NFT_SET_BLACK6}
: ${NFT_SET_SERVICE_PORT:=$DEFAULT_NFT_SET_SERVICE_PORT}
: ${NFT_SET_WHITE4:=$DEFAULT_NFT_SET_WHITE4}
: ${NFT_SET_WHITE6:=$DEFAULT_NFT_SET_WHITE6}
: ${NFT_TABLE_PREFIX:=$DEFAULT_NFT_TABLE_PREFIX}
: ${NFT_TABLE_TYPE:=$DEFAULT_NFT_TABLE_TYPE}
: ${NFT_TABLE:=$NFT_TABLE_PREFIX$_SERVICE}
: ${WHITE4_SUFFIX:=$DEFAULT_WHITE4_SUFFIX}
: ${WHITE6_SUFFIX:=$DEFAULT_WHITE6_SUFFIX}

# Verify environment requirements
[ -s "$FILE_NFT_RULES" ] || error "Invalid file: $FILE_NFT_RULES"
check_nft_timeout "$BAN_TIMEOUT" || BAN_TIMEOUT=$DEFAULT_BAN_TIMEOUT
check_int_list "$SERVICE_PORT" || error "Invalid port: $SERVICE_PORT"

# check nft
which nft >/dev/null 2>&1 || error "Require nft"
_nft_version=$(nft -v | awk '{sub(/v/,"",$2); print $2}')
if [ $(compare_version "$_nft_version" "1.0.7") -eq 1 ]; then
	# nft full function
	_NFT=1
elif [ $(compare_version "$_nft_version" "1.0.0") -eq 1 ]; then
	# nft without destory
	_NFT=2
else
	# nft without --define
	_NFT=3
fi

_action="$2"
_ip="$3"
case "$_action" in
	# Initialization: Stop existing table and load rules from the .nft file
	start|reload|restart)
		stop >/dev/null 2>&1

		( cat "$FILE_NFT_RULES"; printf "\nadd element $NFT_TABLE_TYPE $NFT_TABLE $NFT_SET_SERVICE_PORT {$SERVICE_PORT}\n" ) | nft -f -

		update >/dev/null 2>&1
		;;
	stop)
		stop
		;;
	# Update whitelist sets
	update)
		update >/dev/null 2>&1
		;;
	# Manually ban a specific IP
	ban)
		nft_set_action add $_ip
		;;
	# Manually remove a ban for a specific IP
	unban)
		nft_set_action delete $_ip
		;;
	# Clear all entries from the blacklist sets
	flush)
		nft -f - <<-EOF
			flush set $NFT_TABLE_TYPE $NFT_TABLE $NFT_SET_BLACK4
			flush set $NFT_TABLE_TYPE $NFT_TABLE $NFT_SET_BLACK6
		EOF
		;;
	# Display the full nftables configuration for this service
	show)
		nft list table $NFT_TABLE_TYPE $NFT_TABLE
		;;
	# List all currently banned IP addresses
	list)
		nft list set $NFT_TABLE_TYPE $NFT_TABLE $NFT_SET_BLACK4
		nft list set $NFT_TABLE_TYPE $NFT_TABLE $NFT_SET_BLACK6
		;;
	help|--help|-h)
		usage
		;;
	*)
		;;
esac
