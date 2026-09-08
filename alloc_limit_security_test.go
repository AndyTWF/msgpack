package msgpack

// Security regression tests for the unbounded-allocation DoS (CWE-789/CWE-770).
//
// A MessagePack array/map header declares an element count in as few as 5 bytes
// (e.g. array32 = 0xdd + 4-byte big-endian count, up to ~4.29 billion). The
// decoder must NOT size an allocation directly from that untrusted count.
//
// Each test below gives the decoder a header declaring far more than follows
// it, and checks that what the decoder allocates stays in proportion to the
// data actually supplied rather than to the count in the header.

import (
	"runtime"
	"strconv"
	"testing"
)

// secArray32Header builds a 5-byte array32 header declaring n elements, with NO
// element bytes following it.
func secArray32Header(n uint32) []byte {
	return []byte{0xdd, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// secMap32Header builds a 5-byte map32 header declaring n entries, with no body.
func secMap32Header(n uint32) []byte {
	return []byte{0xdf, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func secMeasureAlloc(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// secAllocCeiling is the most a decode of a handful of bytes may allocate. It
// sits just above what sliceAllocLimit and maxMapSize cost, so that these tests
// fail both if the bounding is removed and if the limits are raised far enough
// to matter.
const secAllocCeiling = 4 << 20

const secDeclared = 10_000_000 // declared by a 5-byte header

// Test that an array decoded into a typed slice allocates in proportion to the
// elements supplied, not to the count the header declares.
func TestSecAllocBounded_TypedSlice(t *testing.T) {
	data := secArray32Header(secDeclared)
	var dst []int64

	got := secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })

	t.Logf("declared=%d elems, allocated=%.1f MiB (cap=%d elems)",
		secDeclared, float64(got)/(1<<20), int(sliceAllocLimit))
	if got > secAllocCeiling {
		t.Fatalf("typed slice allocation not bounded: a %d-byte header allocated %d bytes (> %d). "+
			"sliceAllocLimit bypassed (CWE-789).", len(data), got, secAllocCeiling)
	}
}

// Test the same for an array decoded into an interface{}, which the decoder
// reaches by a different path than a typed slice.
func TestSecAllocBounded_InterfaceSlice(t *testing.T) {
	data := secArray32Header(secDeclared)
	var dst interface{}

	got := secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })

	t.Logf("declared=%d elems, allocated=%.1f MiB", secDeclared, float64(got)/(1<<20))
	if got > secAllocCeiling {
		t.Fatalf("interface{} allocation not bounded: allocated %d bytes (> %d)", got, secAllocCeiling)
	}
}

// Test the same for a map, which is allocated once at its declared size rather
// than grown an element at a time.
func TestSecAllocBounded_Map(t *testing.T) {
	data := secMap32Header(secDeclared)
	var dst map[string]interface{}

	got := secMeasureAlloc(func() { _ = Unmarshal(data, &dst) })

	// a map is allowed more than secAllocCeiling because Go sizes map
	// buckets generously, at roughly 80 bytes an entry against 16 for a
	// slice element
	const mapCeiling = 16 << 20
	t.Logf("declared=%d entries, allocated=%.1f MiB (cap=%d)",
		secDeclared, float64(got)/(1<<20), int(maxMapSize))
	if got > mapCeiling {
		t.Fatalf("map allocation not bounded: allocated %d bytes (> %d)", got, mapCeiling)
	}
}

// Test that a slice with more elements than the limit still decodes in full,
// so that bounding what is allocated up front has not capped the result.
func TestSecHonestLargeSliceRoundTrips(t *testing.T) {
	const n = 1_500_000 // more than sliceAllocLimit

	in := make([]int64, n)
	for i := range in {
		in[i] = int64(i)
	}

	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out []int64
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out) != n {
		t.Fatalf("length mismatch: got %d, want %d", len(out), n)
	}
	if out[0] != 0 || out[n-1] != int64(n-1) {
		t.Fatalf("value mismatch: out[0]=%d out[%d]=%d", out[0], n-1, out[n-1])
	}
}

// Test that a map with more entries than the limit still decodes in full.
func TestSecHonestLargeMapRoundTrips(t *testing.T) {
	const n = 200_000 // more than maxMapSize

	in := make(map[string]int64, n)
	for i := 0; i < n; i++ {
		in[strconv.Itoa(i)] = int64(i)
	}

	b, err := Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out map[string]int64
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out) != n {
		t.Fatalf("length mismatch: got %d, want %d", len(out), n)
	}
	if out["0"] != 0 || out[strconv.Itoa(n-1)] != int64(n-1) {
		t.Fatalf("value mismatch: out[0]=%d out[%d]=%d", out["0"], n-1, out[strconv.Itoa(n-1)])
	}
}
