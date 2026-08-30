package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// decodeJSON reads a JSON request body into a map for assertions.
func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return m
}

// TestRegisterNode: registerNode POSTs {fingerprint, hostname} to /v1/nodes/register with the
// bearer token and parses node_id/node_secret from a 201.
func TestRegisterNode(t *testing.T) {
	var gotPath, gotAuth, gotFP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		gotFP, _ = decodeBody(t, r)["fingerprint"].(string)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"node_id": "node_abc123", "node_secret": "nsec_xyz"})
	}))
	defer srv.Close()

	id, sec, err := registerNode(srv.URL, "ar_ing_tok", "fp_stable_123456")
	if err != nil {
		t.Fatalf("registerNode err: %v", err)
	}
	if id != "node_abc123" || sec != "nsec_xyz" {
		t.Fatalf("parsed id=%q sec=%q", id, sec)
	}
	if gotPath != "/v1/nodes/register" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer ar_ing_tok" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotFP != "fp_stable_123456" {
		t.Errorf("fingerprint = %q", gotFP)
	}
}

// registerNode surfaces a non-201 as an error so callers fall back to a legacy heartbeat.
func TestRegisterNodeNon201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // e.g. older control plane without the endpoint
	}))
	defer srv.Close()
	if _, _, err := registerNode(srv.URL, "t", "fp_123456"); err == nil {
		t.Fatal("expected error on non-201")
	}
}

// TestSendHeartbeatAttested: with a secret present the heartbeat carries node_id+node_secret.
func TestSendHeartbeatAttested(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body = decodeBody(t, r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sendHeartbeat(srv.URL, "ar_ing_tok", &nodeCred{fp: "fp1", nodeID: "node_abc", secret: "nsec_xyz"})
	if body["node_id"] != "node_abc" || body["node_secret"] != "nsec_xyz" {
		t.Fatalf("attested heartbeat body = %v", body)
	}
}

// TestSendHeartbeatLegacy: without a secret the heartbeat sends node_id only (no node_secret key).
func TestSendHeartbeatLegacy(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body = decodeBody(t, r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sendHeartbeat(srv.URL, "t", &nodeCred{fp: "fp1", nodeID: "localhash"})
	if body["node_id"] != "localhash" {
		t.Fatalf("node_id = %v", body["node_id"])
	}
	if _, ok := body["node_secret"]; ok {
		t.Fatalf("legacy heartbeat must not include node_secret: %v", body)
	}
}

// TestSendHeartbeat401Reregister: a 401 while attested (secret revoked/rotated, e.g. control plane
// wiped) triggers a single re-register and retry, and the credential is refreshed in place.
func TestSendHeartbeat401Reregister(t *testing.T) {
	var heartbeats, registers int
	var retryBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/heartbeat":
			heartbeats++
			if heartbeats == 1 {
				w.WriteHeader(http.StatusUnauthorized) // stale secret
				return
			}
			retryBody = decodeBody(t, r)
			w.WriteHeader(http.StatusOK)
		case "/v1/nodes/register":
			registers++
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"node_id": "node_fresh", "node_secret": "nsec_fresh"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cred := &nodeCred{fp: "fp_stable", nodeID: "node_stale", secret: "nsec_stale"}
	sendHeartbeat(srv.URL, "ar_ing_tok", cred)

	if registers != 1 {
		t.Errorf("expected 1 re-register, got %d", registers)
	}
	if heartbeats != 2 {
		t.Errorf("expected 2 heartbeat attempts (initial + retry), got %d", heartbeats)
	}
	if cred.nodeID != "node_fresh" || cred.secret != "nsec_fresh" {
		t.Errorf("credential not refreshed: %+v", cred)
	}
	if retryBody["node_secret"] != "nsec_fresh" {
		t.Errorf("retry did not use fresh secret: %v", retryBody)
	}
}

// A legacy (unattested) heartbeat that 401s must NOT try to re-register — there is no secret to
// refresh, so it stays a best-effort no-op (avoids a pointless second call against a bad token).
func TestSendHeartbeatLegacy401NoReregister(t *testing.T) {
	var registers, heartbeats int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/nodes/register" {
			registers++
		} else {
			heartbeats++
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	sendHeartbeat(srv.URL, "bad_tok", &nodeCred{fp: "fp1", nodeID: "localhash"})
	if registers != 0 {
		t.Errorf("legacy 401 must not re-register, got %d", registers)
	}
	if heartbeats != 1 {
		t.Errorf("expected exactly 1 heartbeat attempt, got %d", heartbeats)
	}
}
