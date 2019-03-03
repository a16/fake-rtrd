package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type exampleResource struct {
	Name    string
	Content string
}

var cases = []*exampleResource{
	{
		"case1",
		"route: 192.168.1.0/24\norigin: AS65001\nsource: TEST\n\nroute: 192.168.2.0/24\norigin: AS65002\nremarks: maxLength 26\nsource: TEST\n\nroute6: 2001:db8:1::/48\norigin: AS65001\nsource: TEST\n\nroute6: 2001:db8:2::/48\norigin: AS65002\nremarks: maxLength 64\nsource: TEST\n\n",
	},
}

var expected = []struct {
	route            string
	ip               string
	prefixLen        int
	maxLengthEnable  int
	maxLengthDisable int
	origin           int
}{
	{
		"192.168.1.0/24",
		"192.168.1.0",
		24,
		32,
		24,
		65001,
	},
	{
		"192.168.2.0/24",
		"192.168.2.0",
		24,
		26,
		26,
		65002,
	},
	{
		"2001:db8:1::/48",
		"2001:db8:1::",
		48,
		128,
		48,
		65001,
	},
	{
		"2001:db8:2::/48",
		"2001:db8:2::",
		48,
		64,
		64,
		65002,
	},
}

func generateFiles() []string {
	files := []string{}
	for _, c := range cases {
		tmpfile, _ := ioutil.TempFile(os.TempDir(), c.Name)
		if _, err := tmpfile.Write([]byte(c.Content)); err != nil {
			log.Fatal(err)
		}
		files = append(files, tmpfile.Name())
		tmpfile.Close()
	}
	return files
}

func removeFiles(files []string) {
	for _, f := range files {
		os.Remove(f)
	}
}

func TestResourceWithUseMaxlen(t *testing.T) {
	assert := assert.New(t)
	files := generateFiles()
	r, _ := newResource(files, true)
	for _, ex := range expected {
		rf, n, maxLen, _ := parseCIDR(ex.route)
		_ = maxLen
		addr := n.IP
		m, _ := n.Mask.Size()
		plen := uint8(m)
		b, _ := r.table[r.currentSN][rf].Get(generateKey(rf, addr, plen))
		bucket := b.(*prefixResource)
		assert.Equal(ex.ip, bucket.prefix.String())
		assert.Equal(ex.prefixLen, int(bucket.prefixLen))
		assert.Equal(ex.maxLengthEnable, int(bucket.values[0].maxLen))
		assert.Equal(ex.origin, int(bucket.values[0].asns[0]))
	}
	removeFiles(files)
}

func TestResourceWithoutUseMaxlen(t *testing.T) {
	assert := assert.New(t)
	files := generateFiles()
	r, _ := newResource(files, false)
	for _, ex := range expected {
		rf, n, maxLen, _ := parseCIDR(ex.route)
		_ = maxLen
		addr := n.IP
		m, _ := n.Mask.Size()
		plen := uint8(m)
		b, _ := r.table[r.currentSN][rf].Get(generateKey(rf, addr, plen))
		bucket := b.(*prefixResource)
		assert.Equal(ex.ip, bucket.prefix.String())
		assert.Equal(ex.prefixLen, int(bucket.prefixLen))
		assert.Equal(ex.maxLengthDisable, int(bucket.values[0].maxLen))
		assert.Equal(ex.origin, int(bucket.values[0].asns[0]))
	}
	removeFiles(files)
}
