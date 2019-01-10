GOPATH?=$(shell go env GOPATH)
FAKE_RTRD_OUTPUT_PATH?=${PWD}
export PATH := $(GOPATH)/bin:$(PATH)

GITCOMMIT?=$(shell git describe --always)
LDFLAGS=-ldflags "-X main.version=${GITCOMMIT} -extldflags \"-static\""

PKG_LIST = $(shell go list ./... | grep -v /vendor/)

all: install

install:
	CGO_ENABLED=0 go build -v ${LDFLAGS} -a -tags netgo -installsuffix netgo -o ${FAKE_RTRD_OUTPUT_PATH}/fake-rtrd

.PHONY: dep
dep:
ifeq ($(shell command -v dep 2> /dev/null),)
	go get -u -v github.com/golang/dep/cmd/dep
endif
	dep ensure

.PHONY: test
test:
	go test -v $(PKG_LIST)
