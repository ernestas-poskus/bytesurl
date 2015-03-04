bytesurl
=========

Standard library URL struct converted into bytes

[![Build Status](https://travis-ci.org/ernestas-poskus/bytesurl.svg)](https://travis-ci.org/ernestas-poskus/bytesurl)
[![GoDoc](http://godoc.org/github.com/ernestas-poskus/bytesurl?status.svg)](http://godoc.org/github.com/ernestas-poskus/bytesurl)
[![BSD License](http://img.shields.io/badge/license-BSD-blue.svg)](http://opensource.org/licenses/BSD)

## Benchmark

```go
type BenchmarkResult struct {
	N         int           // The number of iterations.
	T         time.Duration // The total time taken.
	Bytes     int64         // Bytes processed in one iteration.
	MemAllocs uint64        // The total number of memory allocations.
	MemBytes  uint64        // The total number of bytes allocated.
}
```

### Bytes URL

| Function | operations | ns/op | B/op | allocs/op |
| -------- | ---------- | ----- | ------ | ------- |
| BenchmarkString **string() type conversion** | 200000 | 10069 ns/op | **2192** B/op | **24** allocs/op |
| BenchmarkBytes | 200000 | 9642 ns/op | **2192** B/op | **24** allocs/op |


### Standard URL library

| Function | operations | ns/op | B/op | allocs/op |
| -------- | ---------- | ----- | ------ | ------- |
| BenchmarkString | 200000 | 9239 ns/op | **2293** B/op | **42** allocs/op |

***

### Improvements

> Standard library takes a little less time per operation than **bytesurl** but on the other hand **bytesurl** processes less bytes per operation and allocates less memory.
