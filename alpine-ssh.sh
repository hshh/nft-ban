#!/bin/sh
# version: 20260407.02
LOG_FILE="/var/log/messages"
RUN="nft.sh"

export PATH=/sbin:/bin:/usr/sbin:/usr/bin
_currdir=$(cd "$(dirname "$0")" && pwd)
cd "$_currdir" || exit 1

tail -Fn0 "$LOG_FILE" | awk -v cmd="$_currdir/$RUN" -f ssh.awk
