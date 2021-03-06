# fake-rtrd

[![Build Status](https://travis-ci.org/a16/fake-rtrd.svg?branch=master)](https://travis-ci.org/a16/fake-rtrd)

fake-rtrd is a daemon which imports files which is written in RPSL (eg. IRRdb files) instead of ROAs and provides them via RPKI-RTR.
It would be useful for RPKI-RTR testing with RTR clients. Do not use this in production because these data are not validated.

### Installation

```bash
% go get github.com/a16/fake-rtrd
```

### Usage

```bash
Usage:
  fake-rtrd [OPTIONS] [RPSLFILES]...

Application Options:
  -d, --debug     Show verbose debug information (default: false)
  -i, --interval= Specify minutes for reloading pseudo ROA table with crontab style
  -p, --port=     Specify listen port for RTR (default: 323)
  -q, --quiet     Quiet mode (default: false)

Help Options:
  -h, --help      Show this help message
```

First, you need to prepare a RPSL file. At least, route(6) field, origin field, and source field are required in a object.
Let's say its file name is ```test.db```.

```bash
route: 210.173.160.0/19
origin: AS7521
source: TEST

route6: 2001:3a0::/32
origin: AS7521
source: TEST

```

Then type the following command to run fake-rtrd.

```bash
% sudo fake-rtrd test.db
```

By default, file has never been reloaded after started. If you want to reload it, Send HUP to it, or Use -i option. It'll send Serial Notify to clients when you updated it.

If you want to load it from IRRd continuously, add commands like below and run ```fake-rtrd```

```bash
% crontab -e
*/5 * * * * wget -q -O - ftp://ftp.nic.ad.jp/jpirr/jpirr.db.gz | gunzip -c > /tmp/jpirr.db 2>/dev/null

% sudo fake-rtrd /tmp/jpirr.db
```



