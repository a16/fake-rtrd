# fake-rtrd

[![Build Status](https://travis-ci.org/a16/fake-rtrd.svg?branch=master)](https://travis-ci.org/a16/fake-rtrd)

fake-rtrd is a daemon which imports files which is written in RPSL (eg. IRRdb files) instead of ROAs and provides them via RPKI-RTR.
It would be useful for RPKI-RTR testing. Do not use this in production because these data are not validated.

### Installation

```bash
% go get github.com/a16/fake-rtrd
```

### Usage
First, you should prepare a RPSL file. At least, route(6) field, origin field, and source field are required in a object.
Let's say its name is ```test.db```.

```bash
route: 210.173.160.0/19
origin: AS7521
source: TEST

route6: 2001:3a0::/32
origin: AS7521
source: TEST

```

Then run the following command.

```bash
% sudo fake-rtrd test.db
```

By default, file is reloaded every 5 minutes. It'll send Serial Notify to clients when you updated it.

If you want to load it from IRRd continuously, add commands like below and run ```fake-rtrd```

```bash
% crontab -e
*/5 * * * * wget -q -O - ftp://ftp.nic.ad.jp/jpirr/jpirr.db.gz | gunzip -c > /tmp/jpirr.db 2>/dev/null

% sudo fake-rtrd /tmp/jpirr.db
```



