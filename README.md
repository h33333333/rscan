# rscan
`rscan` is a simple tool to quickly scan a local or remote host for the open ports.
## Motivation
This project was mainly made to save people (and myself) some time during port scanning. There is a great tool called `nmap`, which is considered the gold standard for network discovery and scanning, and `rscan` doesn't have all the features `nmap` does, but when it comes to a simple port scanning - `rscan` can do it a lot quicker.
## How rscan works
For now, `rscan` can only do the SYN scan (or Half-open scan). It is often called "Stealth scan", because TCP handshake is never completed. Also, by default it checks if the host is up by pinging the target before the scan begins (this can be changed, check `--help` for more info). `rscan` is faster because it is working in multithreading mode (by default,the number of threads is 4, but you can change this. For more info refer to the  `--help` page)
## Installation
Currently, the only way to install `rscan` is through cargo:
```sh
$ cargo install rscan
```
## Usage
Scanning the `google.com` using the `en0` interface:
```sh
$ sudo rscan -i en0 google.com
DNS lookup results: google.com is at 216.58.209.14
Host is up, starting scan...
Scanning 216.58.209.14 using SYN scan:
 *Interface: en0
 *Threads: 4
 *Port: 58058
---
Stats: 65533 filtered/closed port(s) (RST or no response), 2 open port(s)
PORT    STATUS
80      Open
443     Open
```
Scan was completed in 10 seconds (it is worth noticing that this strongly depends on the load of your network and the current CPU usage).
## Known problems and limitations
- `rscan` should always be run using the `sudo`. This happens because `rscan` is using the raw sockets behind the scenes.
- You should always explicitly specify the network interface
- No IPv6 support
- No way to change the delay between each TCP packet
- Only one scan type is present currently
- As this project heavily depends on the [libpnet](https://github.com/libpnet/libpnet) package, building `rscan` on Windows is not as trivial as it is on the Unix based systems. For more inforamtion please refer to the [libpnet's usage section](https://github.com/libpnet/libpnet#usage)
