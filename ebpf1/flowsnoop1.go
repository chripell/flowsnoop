// Code generated by "esc -o flowsnoop1.go -pkg ebpf1 -private c/flowsnoop1.c"; DO NOT EDIT.

package ebpf1

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"sync"
	"time"
)

type _escLocalFS struct{}

var _escLocal _escLocalFS

type _escStaticFS struct{}

var _escStatic _escStaticFS

type _escDirectory struct {
	fs   http.FileSystem
	name string
}

type _escFile struct {
	compressed string
	size       int64
	modtime    int64
	local      string
	isDir      bool

	once sync.Once
	data []byte
	name string
}

func (_escLocalFS) Open(name string) (http.File, error) {
	f, present := _escData[path.Clean(name)]
	if !present {
		return nil, os.ErrNotExist
	}
	return os.Open(f.local)
}

func (_escStaticFS) prepare(name string) (*_escFile, error) {
	f, present := _escData[path.Clean(name)]
	if !present {
		return nil, os.ErrNotExist
	}
	var err error
	f.once.Do(func() {
		f.name = path.Base(name)
		if f.size == 0 {
			return
		}
		var gr *gzip.Reader
		b64 := base64.NewDecoder(base64.StdEncoding, bytes.NewBufferString(f.compressed))
		gr, err = gzip.NewReader(b64)
		if err != nil {
			return
		}
		f.data, err = ioutil.ReadAll(gr)
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (fs _escStaticFS) Open(name string) (http.File, error) {
	f, err := fs.prepare(name)
	if err != nil {
		return nil, err
	}
	return f.File()
}

func (dir _escDirectory) Open(name string) (http.File, error) {
	return dir.fs.Open(dir.name + name)
}

func (f *_escFile) File() (http.File, error) {
	type httpFile struct {
		*bytes.Reader
		*_escFile
	}
	return &httpFile{
		Reader:   bytes.NewReader(f.data),
		_escFile: f,
	}, nil
}

func (f *_escFile) Close() error {
	return nil
}

func (f *_escFile) Readdir(count int) ([]os.FileInfo, error) {
	if !f.isDir {
		return nil, fmt.Errorf(" escFile.Readdir: '%s' is not directory", f.name)
	}

	fis, ok := _escDirs[f.local]
	if !ok {
		return nil, fmt.Errorf(" escFile.Readdir: '%s' is directory, but we have no info about content of this dir, local=%s", f.name, f.local)
	}
	limit := count
	if count <= 0 || limit > len(fis) {
		limit = len(fis)
	}

	if len(fis) == 0 && count > 0 {
		return nil, io.EOF
	}

	return fis[0:limit], nil
}

func (f *_escFile) Stat() (os.FileInfo, error) {
	return f, nil
}

func (f *_escFile) Name() string {
	return f.name
}

func (f *_escFile) Size() int64 {
	return f.size
}

func (f *_escFile) Mode() os.FileMode {
	return 0
}

func (f *_escFile) ModTime() time.Time {
	return time.Unix(f.modtime, 0)
}

func (f *_escFile) IsDir() bool {
	return f.isDir
}

func (f *_escFile) Sys() interface{} {
	return f
}

// _escFS returns a http.Filesystem for the embedded assets. If useLocal is true,
// the filesystem's contents are instead used.
func _escFS(useLocal bool) http.FileSystem {
	if useLocal {
		return _escLocal
	}
	return _escStatic
}

// _escDir returns a http.Filesystem for the embedded assets on a given prefix dir.
// If useLocal is true, the filesystem's contents are instead used.
func _escDir(useLocal bool, name string) http.FileSystem {
	if useLocal {
		return _escDirectory{fs: _escLocal, name: name}
	}
	return _escDirectory{fs: _escStatic, name: name}
}

// _escFSByte returns the named file from the embedded assets. If useLocal is
// true, the filesystem's contents are instead used.
func _escFSByte(useLocal bool, name string) ([]byte, error) {
	if useLocal {
		f, err := _escLocal.Open(name)
		if err != nil {
			return nil, err
		}
		b, err := ioutil.ReadAll(f)
		_ = f.Close()
		return b, err
	}
	f, err := _escStatic.prepare(name)
	if err != nil {
		return nil, err
	}
	return f.data, nil
}

// _escFSMustByte is the same as _escFSByte, but panics if name is not present.
func _escFSMustByte(useLocal bool, name string) []byte {
	b, err := _escFSByte(useLocal, name)
	if err != nil {
		panic(err)
	}
	return b
}

// _escFSString is the string version of _escFSByte.
func _escFSString(useLocal bool, name string) (string, error) {
	b, err := _escFSByte(useLocal, name)
	return string(b), err
}

// _escFSMustString is the string version of _escFSMustByte.
func _escFSMustString(useLocal bool, name string) string {
	return string(_escFSMustByte(useLocal, name))
}

var _escData = map[string]*_escFile{

	"/c/flowsnoop1.c": {
		name:    "flowsnoop1.c",
		local:   "c/flowsnoop1.c",
		size:    3402,
		modtime: 1588427325,
		compressed: `
H4sIAAAAAAAC/9xWXW/jNhB8rn7FFgUMKbEtuw3UQ3024Hy0Ddo7G4nblyAgZGoVE1ZIlaRUB3f+7wUp
yrF0dtrgDmjRJ5vc1e7McJbSN4zTrEgQ3hZxzsKM8WIT5lrGFPuriXcwrGl+NMZeCpVRM8hRh0rQdXN3
SWmYS6GF2faUlgXVQAXnRH3wAIrvvgUlKWH5yK0SpevVMLKxXEhdr010t34DtjIV2cjbjrzz+Y/k5+vb
xeynm+k73/RAqpngqguNvl04/+3il6vFbTBqIIocpDcO0d0wund9KlC7jS8FLGogiz6BFmtGgfGMcawT
Nc1XiYQTtV4SLUi1NDWVrlPUmiyLNLU5gWcohSEUXOl4mSFM59d9KFGy9Aky8WAbmKrE1AmgNwFbWsZc
GT5khXGC0g/6HoBEXUgOfgtL4Kv1sjcxmXAK9n/7+WDkbY8wYg1C7IvwYS06HPWfQq5fIsOOcmk+/CKT
Mmpyset/h42D8lo+GhJBqCi4PvMPIO7alAx5AAZ6UzuWwxga52g42ongij1wTICuYgknOYUx+K3NAKqx
b8yq/YExfNiaEEvB93N6N7iHDgw26SCAr8cw2JwNgq/CE7iel2cgePYEJ6EHsBOlNzQPm0r9ei5hDCzv
TZ7H1MWryXdRFSeJ3IWqO8CFkjpkIe2XgvEYIvj4Edqbw+8D6HQsLjg8JJZMJSy0513TPXHd1Nfq7mE3
1WBsnupNlCgkxb2E+o6qExJU9r7aAmYKXd92qcHhAnZ767Rx11mfcSrxEbm2l1zX+mT0bM7BMatFr7Ga
M3bTbNWgfabdon/qt2jnt+i438ITWMwuZz8AXSFdg14x1QWmgSngwjSUEg0hDnGWAY0Vqn5V6JBTOW70
qrLcMk9JLsUSicQ48fd824Vh1IXOzrvBsfTKy3vpyS7dcm4hcI7+ZPf/b+no1Z7GP4o48yuPKUm7zm6J
0pWhnZ3NX2bqpEL6bDwYAXvLR8BOTwMLzhyDkvSO3RsJE6Xv2H3glHath8dglIIlu9l6cbR26LCsYF1e
/X5bu+Di3fw2MDZ2emACyyfodJpur7MHxhCH3i/HcvfeMwaR0fVvc6NjuVvPW9xML67ms+v3CzK/mZ1f
+Rx1FzhqlhKJFFmJxNgL3Ds3lg/KDGMqxSOE6kmFa5QcszDBZfEQmq9mxh9CLJFrFZqvW1drE6ZCPsba
OMWol2BZfxke0NpcPe3twDbvTdR6Wb9HFnNyOV1Mya+zC3JzNb0kF7P3tws/wbILPH5EM6vWd8/napSo
6tiTNGfYcsToBVVIgiVROpaabB6Z/jxZWsX+iwJBz/2v7SnSVBktDur2VwAAAP//zz/rtkoNAAA=
`,
	},
}

var _escDirs = map[string][]os.FileInfo{}
