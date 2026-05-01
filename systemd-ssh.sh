#!/bin/sh
# version: 20260407.02
RUN="nft.sh"

export PATH=/sbin:/bin:/usr/sbin:/usr/bin
_currdir=$(cd "$(dirname "$0")" && pwd)
cd "$_currdir" || exit 1

journalctl -fn0 -u ssh.service -u sshd.service | awk -v cmd="$_currdir/$RUN" -f ssh.awk
