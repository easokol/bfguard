# bfguard
nftables based linux brute-force guard utility

A lightweight Go daemon for Linux that automatically blacklists IP addresses which attempt to connect to specified TCP or UDP ports.  
It uses **nftables** to enforce the blacklist, supports both IPv4 and IPv6, and allows whitelisting of trusted networks.

## Features

- Listens on user‑defined TCP and UDP ports.
- Extracts the source IP address from each incoming connection or packet.
- Adds the IP to an nftables set (`blacklist_v4` / `blacklist_v6`) with a **48‑hour timeout** (unless the IP is whitelisted).
- Once blacklisted, all subsequent traffic from that IP is **rejected with ICMP port‑unreachable** (or ICMPv6 equivalent).
- Whitelist support (CIDR ranges) – whitelisted IPs are never blacklisted.
- Separate nftables table `nft-baserules` that **drops packets with invalid connection state** (`ct state invalid`), with named counters for monitoring.
- All nftables rules are created automatically on startup.
- Graceful shutdown on SIGINT / SIGTERM.

## Requirements

- Linux with **nftables** support (kernel ≥ 3.13, but modern distributions are fine).
- Go 1.18+ (to build from source).
- **Root privileges** – because the program manipulates nftables and listens on privileged ports.

## Installation

### Build from source

```bash
git clone https://github.com/easokol/bfguard.git
cd bfguard
go build -o bfguard main.go