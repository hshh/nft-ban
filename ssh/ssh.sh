#!/bin/sh
# version: 20260503.01
ROOTDIR="/usr/local/nft-ban"
NFT="nft.sh"
SERVICE="ssh"
AWK="ssh.awk"
LOG_FILE="/var/log/messages"

export PATH=/sbin:/bin:/usr/sbin:/usr/bin
_nft="$ROOTDIR/$NFT"
_awk="$ROOTDIR/$SERVICE/$AWK"
[ -x "$_nft" ] || exit 1
[ -s "$_awk" ] || exit 1

if hash journalctl 2>/dev/null; then
	journalctl -fn0 -u ssh.service -u sshd.service | awk -v cmd="$_nft" -f "$_awk"
else
	tail -Fn0 "$LOG_FILE" | awk -v cmd="$_nft" -f "$_awk"
fi
