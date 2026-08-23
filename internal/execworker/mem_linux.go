//go:build linux

package execworker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var errMemoryPattern = errors.New("invalid memory scan pattern")

const (
	maxMemoryPatternBytes = 4096
	memoryReadChunk       = 64 << 10
	maxMemoryContextBytes = 16
)

type memoryRegion struct {
	start uint64
	end   uint64
}

func scanProcessMemory(pid int, expectedStarttime uint64, request MemoryScan, limits Limits) ([]MemoryMatch, int64, error) {
	pattern, err := decodeMemoryPattern(request)
	if err != nil {
		return nil, 0, errMemoryPattern
	}
	if err := requireStarttime(pid, expectedStarttime); err != nil {
		return nil, 0, err
	}
	regions, err := readableMemoryRegions(pid, limits.ScanRegions)
	if err != nil {
		return nil, 0, err
	}
	memory, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, 0, err
	}
	defer memory.Close()
	matches := make([]MemoryMatch, 0, limits.ScanResults)
	var scanned int64
	for regionIndex, region := range regions {
		if scanned >= limits.ScanBytes || len(matches) >= limits.ScanResults {
			break
		}
		regionBytes := int64(region.end - region.start)
		if remaining := limits.ScanBytes - scanned; regionBytes > remaining {
			regionBytes = remaining
		}
		regionMatches, readBytes := scanMemoryRegion(memory, region, regionIndex, regionBytes, pattern, request, limits.ScanResults-len(matches))
		matches = append(matches, regionMatches...)
		scanned += readBytes
	}
	if err := requireStarttime(pid, expectedStarttime); err != nil {
		return nil, 0, err
	}
	return matches, scanned, nil
}

func decodeMemoryPattern(request MemoryScan) ([]byte, error) {
	var (
		value []byte
		err   error
	)
	switch request.Mode {
	case MemoryHex:
		if request.Pattern == "" || strings.ToLower(request.Pattern) != request.Pattern || len(request.Pattern)%2 != 0 {
			return nil, errMemoryPattern
		}
		value, err = hex.DecodeString(request.Pattern)
		if err == nil && hex.EncodeToString(value) != request.Pattern {
			err = errMemoryPattern
		}
	case MemoryBase64:
		value, err = base64.StdEncoding.DecodeString(request.Pattern)
		if err == nil && base64.StdEncoding.EncodeToString(value) != request.Pattern {
			err = errMemoryPattern
		}
	default:
		return nil, errMemoryPattern
	}
	if err != nil || len(value) == 0 || len(value) > maxMemoryPatternBytes {
		return nil, errMemoryPattern
	}
	return value, nil
}

func readableMemoryRegions(pid, max int) ([]memoryRegion, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	regions := make([]memoryRegion, 0, max)
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "r") {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, startErr := strconv.ParseUint(bounds[0], 16, 64)
		end, endErr := strconv.ParseUint(bounds[1], 16, 64)
		if startErr != nil || endErr != nil || end <= start || start > uint64(^uint(0)>>1) {
			continue
		}
		regions = append(regions, memoryRegion{start: start, end: end})
		if len(regions) == max {
			break
		}
	}
	return regions, nil
}

func scanMemoryRegion(memory *os.File, region memoryRegion, regionIndex int, budget int64, pattern []byte, request MemoryScan, maxResults int) ([]MemoryMatch, int64) {
	matches := make([]MemoryMatch, 0)
	buffer := make([]byte, memoryReadChunk)
	var carry []byte
	var consumed int64
	for consumed < budget && len(matches) < maxResults {
		want := int64(len(buffer))
		if remaining := budget - consumed; want > remaining {
			want = remaining
		}
		n, err := unix.Pread(int(memory.Fd()), buffer[:int(want)], int64(region.start)+consumed)
		if n <= 0 {
			break
		}
		combined := make([]byte, len(carry)+n)
		copy(combined, carry)
		copy(combined[len(carry):], buffer[:n])
		combinedBase := consumed - int64(len(carry))
		for searchAt := 0; searchAt <= len(combined)-len(pattern) && len(matches) < maxResults; {
			found := bytes.Index(combined[searchAt:], pattern)
			if found < 0 {
				break
			}
			found += searchAt
			offset := combinedBase + int64(found)
			// A match wholly inside carry was already reported in the prior chunk.
			if offset+int64(len(pattern)) > consumed {
				matches = append(matches, memoryMatch(regionIndex, offset, pattern, combined, found, request))
			}
			searchAt = found + 1
		}
		consumed += int64(n)
		carryBytes := len(pattern) - 1
		if carryBytes > len(combined) {
			carryBytes = len(combined)
		}
		carry = append(carry[:0], combined[len(combined)-carryBytes:]...)
		if err != nil || n < int(want) {
			break
		}
	}
	return matches, consumed
}

func memoryMatch(regionIndex int, offset int64, pattern, combined []byte, found int, request MemoryScan) MemoryMatch {
	digestInput := make([]byte, 12+len(pattern))
	binary.BigEndian.PutUint32(digestInput[:4], uint32(regionIndex))
	binary.BigEndian.PutUint64(digestInput[4:12], uint64(offset))
	copy(digestInput[12:], pattern)
	sum := sha256.Sum256(digestInput)
	match := MemoryMatch{RegionIndex: regionIndex, Offset: offset, Digest: hex.EncodeToString(sum[:])}
	if !request.IncludeContext {
		return match
	}
	start := found
	if len(pattern) < maxMemoryContextBytes {
		start -= (maxMemoryContextBytes - len(pattern)) / 2
	}
	if start < 0 {
		start = 0
	}
	if start > len(combined) {
		start = len(combined)
	}
	end := start + maxMemoryContextBytes
	if end > len(combined) {
		end = len(combined)
	}
	contextBytes := combined[start:end]
	if request.Mode == MemoryHex {
		match.Context = hex.EncodeToString(contextBytes)
	} else {
		match.Context = base64.StdEncoding.EncodeToString(contextBytes)
	}
	match.ContextMode = request.Mode
	match.Sensitive = true
	return match
}

func requireStarttime(pid int, expected uint64) error {
	actual, err := procStarttime(pid)
	if err != nil || actual != expected {
		return errProcessIdentity
	}
	return nil
}
