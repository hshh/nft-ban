# nft-ban
A lightweight tool to block SSH brute-force attacks using `nftables`.

## Introduction
`nft-ban` is a script-based utility that leverages the Linux `nftables` framework to automatically detect and block SSH brute-force attempts. It supports both IPv4 and IPv6, allows subnet-level banning, and includes whitelisting capabilities.

## Features
- **Dual Stack**: Full support for IPv4 and IPv6.
- **Subnet Banning**: Ability to ban entire subnets (e.g., /24) to prevent distributed attacks from the same range.
- **Whitelisting**: Prevent accidental lockout by defining trusted IP ranges.
- **Service Support**: Native scripts for both `systemd` and `openrc`.

## Installation

### 1. Clone and Deploy
```bash
git clone https://github.com/hshh/nft-ban.git nft-ban
sudo cp -a nft-ban/. /usr/local/nft-ban
cd /usr/local/nft-ban
```

### 2. Service Setup

#### For systemd-based Linux (Ubuntu, Debian, CentOS, etc.):
```bash
sudo cp nft-ssh.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start nft-ssh
sudo systemctl enable nft-ssh
```

#### For openrc-based Linux (Alpine, Gentoo, etc.):
```bash
install -c nft-ssh.openrc /etc/init.d/nft-ssh
rc-update add nft-ssh default
rc-service nft-ssh start
```

## Configuration
Edit the `/usr/local/nft-ban/ssh.conf` file to adjust settings:

| Variable | Description |
| :--- | :--- |
| `SERVICE_PORT` | The port your SSH service is listening on (usually 22). |
| `BAN_IPV4_SUBNET` | IPv4 CIDR prefix for banning (e.g., `32` for single IP, `24` for subnet). |
| `BAN_IPV6_SUBNET` | IPv6 CIDR prefix for banning (e.g., `128` or `64`). |
| `DEBUG` | Enable debug logging (set to 1). |
| `DEFAULT_NFT_TABLE_PREFIX` | Prefix for the nftables table name. |
| `DEFAULT_NFT_TABLE_TYPE` | Type of nftables table (ip or inet). |
| `DEFAULT_NFT_BLACK4` | Name of the IPv4 blacklist set. |
| `DEFAULT_NFT_BLACK6` | Name of the IPv6 blacklist set. |
| `DEFAULT_NFT_WHITE4` | Name of the IPv4 whitelist set. |
| `DEFAULT_NFT_WHITE6` | Name of the IPv6 whitelist set. |

Create ssh-white4.txt and ssh-white6.txt by sampling from white4.txt and white6.txt, respectively.

## License
BSD-3-Clause license
