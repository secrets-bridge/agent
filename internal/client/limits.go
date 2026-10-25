package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Response size limits (AGT-N-08). Every body the agent reads from the CP
// goes through decodeJSON with one of these caps, so a misbehaving CP, or
// anything answering in its place, can't make the agent buffer an
// unbounded body.
const (
	// maxSmallResponse covers heartbeat, enroll, rotation, DEK and
	// post-wrap acknowledgements: a handful of short fields.
	maxSmallResponse int64 = 64 << 10
	// maxJobResponse covers a claimed job: ids, target config, key names
	// and the wrap list of one request.
	maxJobResponse int64 = 1 << 20
	// maxWrapResponse covers one sealed wrap. The api caps request bodies
	// at 4 MiB, so a single value plus base64 and the envelope stays well
	// under this.
	maxWrapResponse int64 = 8 << 20
	// maxBulkResponse covers the discovery batch ack (one id per item).
	maxBulkResponse int64 = 8 << 20
	// maxDrain is how much of an unread body drainAndClose will consume
	// to keep the connection reusable before giving up on it.
	maxDrain int64 = 64 << 10
)

// ErrResponseTooLarge is returned when a CP response body exceeds the
// limit for its endpoint. The body is discarded, never parsed.
var ErrResponseTooLarge = errors.New("client: response body exceeds the size limit")

// decodeJSON reads at most limit bytes of r and unmarshals them into v.
// A body larger than limit is rejected with ErrResponseTooLarge instead
// of being truncated into something that might still parse. The raw
// buffer is zeroed afterwards because some responses (a DEK, a sealed
// wrap) carry key material.
func decodeJSON(r io.Reader, limit int64, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	defer Zero(data)
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return fmt.Errorf("%w (%d bytes)", ErrResponseTooLarge, limit)
	}
	return json.Unmarshal(data, v)
}

// refuseRedirect is the CheckRedirect policy for every CP client: never
// follow. Go's client re-sends custom headers such as X-Agent-Secret (and,
// on 307/308, the request body with the enrollment token) to whatever
// host Location names, including an https -> http downgrade (AGT-N-02).
// Returning ErrUseLastResponse hands the 3xx back to the caller, which
// treats it as an error.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
