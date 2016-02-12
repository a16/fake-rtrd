# fake-rtrd

[![Build Status](https://travis-ci.org/a16/fake-rtrd.svg?branch=master)](https://travis-ci.org/a16/fake-rtrd)

fake-rtrd is a daemon which imports files which is written in RPSL (eg. IRRdb files) instead of ROAs and provides them via RPKI-RTR.
It would be useful for RPKI-RTR testing. Do not use this in production because these data are not validated.

### Install
```bash
% go get github.com/a16/fake-rtrd
```
