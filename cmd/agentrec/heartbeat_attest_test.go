package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// decodeBody reads a JSON request body into a map for assertions.
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

// registerNode surfaces a non-201 as an error so the caller skips the heartbeat and retries later.
func TestRegisterNodeNon201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, _, err := registerNode(srv.URL, "t", "fp_123456"); err == nil {
		t.Fatal("expected error on non-201")
	}
}

// TestSendHeartbeatAttested: with a credential already in hand, the heartbeat carries
// node_id+node_secret and no re-registration happens.
func TestSendHeartbeatAttested(t *testing.T) {
	var body map[string]any
	var registers int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/nodes/register" {
			registers++
		}
		body = decodeBody(t, r)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sendHeartbeat(srv.URL, "ar_ing_tok", &nodeCred{fp: "fp1", nodeID: "node_abc", secret: "nsec_xyz"})
	if registers != 0 {
		t.Errorf("already-credentialed node must not re-register, got %d", registers)
	}
	if body["node_id"] != "node_abc" || body["node_secret"] != "nsec_xyz" {
		t.Fatalf("attested heartbeat body = %v", body)
	}
}

// TestSendHeartbeatRegistersWhenUncredentialed: an uncredentialed node registers lazily on its
// first heartbeat, stores the credential, and sends an attested ping.
func TestSendHeartbeatRegistersWhenUncredentialed(t *testing.T) {
	var registers int
	var hbBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/nodes/register":
			registers++
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"node_id": "node_new", "node_secret": "nsec_new"})
		case "/v1/heartbeat":
			hbBody = decodeBody(t, r)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cred := &nodeCred{fp: "fp_stable"}
	sendHeartbeat(srv.URL, "ar_ing_tok", cred)
	if registers != 1 {
		t.Errorf("expected 1 registration, got %d", registers)
	}
	if cred.nodeID != "node_new" || cred.secret != "nsec_new" {
		t.Errorf("credential not stored: %+v", cred)
	}
	if hbBody["node_id"] != "node_new" || hbBody["node_secret"] != "nsec_new" {
		t.Errorf("heartbeat not attested: %v", hbBody)
	}
}

// TestSendHeartbeatSkipsWhenRegisterFails: if registration fails while uncredentialed, NO heartbeat
// is sent — an unattested node can't be metered, so the tick is skipped and retried next time.
func TestSendHeartbeatSkipsWhenRegisterFails(t *testing.T) {
	var registers, heartbeats int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/nodes/register" {
			registers++
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		heartbeats++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sendHeartbeat(srv.URL, "ar_ing_tok", &nodeCred{fp: "fp_stable"})
	if registers != 1 {
		t.Errorf("expected 1 registration attempt, got %d", registers)
	}
	if heartbeats != 0 {
		t.Errorf("expected NO heartbeat when unregistered, got %d", heartbeats)
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
