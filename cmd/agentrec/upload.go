package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"agentrec/internal/probe"
	"agentrec/internal/record"
)

/* recordingDoc is the ingest API wire format: a session plus its tool calls. */
type recordingDoc struct {
	Session  string         `json:"session"`
	ID       uint64         `json:"session_id"`
	RootPid  uint32         `json:"root_pid"`
	Duration float64        `json:"duration_s"`
	Calls    []*record.Call `json:"calls"`
	/* NodeFP is this host's stable fingerprint (same value sent to /v1/nodes/register).
	   The server hashes it and resolves it to the attested node, so recordings can be
	   filtered by node in the console. Works in both watch and trace modes. */
	NodeFP string `json:"node_fp,omitempty"`
}

func sessionDoc(s *record.Session) recordingDoc {
	return recordingDoc{s.Name, s.ID, s.RootPid, s.Duration(), s.Calls(), nodeID()}
}

/* ingestResponse is the subset of the API reply we surface to the operator. */
type ingestResponse struct {
	SessionID    string `json:"session_id"`
	Queued       bool   `json:"queued"`
	EventCount   int    `json:"event_count"`
	FindingCount int    `json:"finding_count"`
	CritCount    int    `json:"crit_count"`
	Error        string `json:"error"`
}

/* resolveTarget fills endpoint/token from flags, falling back to the environment. */
func resolveTarget(endpoint, token string) (string, string) {
	if endpoint == "" {
		endpoint = os.Getenv("AGENTREC_ENDPOINT")
	}
	if token == "" {
		token = os.Getenv("AGENTREC_TOKEN")
	}
	return strings.TrimRight(endpoint, "/"), token
}

/* uploadRecording ships one recording to <endpoint>/v1/ingest, retrying transient failures. */
func uploadRecording(endpoint, token string, body []byte) error {
	if endpoint == "" || token == "" {
		return errors.New("endpoint and token are both required (flags or AGENTREC_ENDPOINT / AGENTREC_TOKEN)")
	}
	url := endpoint + "/v1/ingest"
	client := &http.Client{Timeout: 30 * time.Second}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "agentrec-agent/1")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var ir ingestResponse
				_ = json.Unmarshal(respBody, &ir)
				if ir.Queued {
					fmt.Fprintf(os.Stderr, "agentrec: uploaded to %s — session %s queued for processing\n", endpoint, ir.SessionID)
				} else {
					fmt.Fprintf(os.Stderr,
						"agentrec: uploaded to %s — session %s (%d events, %d findings, %d critical)\n",
						endpoint, ir.SessionID, ir.EventCount, ir.FindingCount, ir.CritCount)
				}
				return nil
			}
			if resp.StatusCode == 401 {
				return fmt.Errorf("ingest rejected the token (401): check AGENTREC_TOKEN")
			}
			if resp.StatusCode < 500 {
				return fmt.Errorf("ingest failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
			}
			lastErr = fmt.Errorf("ingest server error (%d)", resp.StatusCode)
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
	}
	return fmt.Errorf("upload failed after 3 attempts: %w", lastErr)
}

/* enforceRulesResp is the control plane's enforceable block rules for this token's workspace. */
type enforceRulesResp struct {
	Version   string `json:"version"`
	Total     int    `json:"total"`
	Truncated bool   `json:"truncated"`
	Rules     []struct {
		Event   string `json:"event"`
		Op      string `json:"op"`
		Pattern string `json:"pattern"`
	} `json:"rules"`
}

/* fetchBlockRules pulls the workspace's block rules, maps them to kernel form, and returns the set version. */
func fetchBlockRules(endpoint, token string) (string, []probe.BlockRule, error) {
	if endpoint == "" || token == "" {
		return "", nil, errors.New("endpoint and token are required")
	}
	req, err := http.NewRequest(http.MethodGet, endpoint+"/v1/enforce/rules", nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "agentrec-agent/1")

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("enforce/rules failed (%d)", resp.StatusCode)
	}
	var er enforceRulesResp
	if err := json.Unmarshal(b, &er); err != nil {
		return "", nil, fmt.Errorf("decoding enforce/rules: %w", err)
	}
	if er.Truncated {
		fmt.Fprintf(os.Stderr, "agentrec: policy: workspace has %d enforceable block rules, only the first %d are enforced in-kernel\n", er.Total, probe.MaxBlockRules)
	}
	evCode := map[string]uint8{"open": probe.EvOpen, "connect": probe.EvConnect, "exec": probe.EvExec, "unlink": probe.EvUnlink}
	opCode := map[string]uint8{"suffix": probe.OpSuffix, "prefix": probe.OpPrefix, "equals": probe.OpEquals}
	var out []probe.BlockRule
	for _, r := range er.Rules {
		ev, ok1 := evCode[r.Event]
		op, ok2 := opCode[r.Op]
		if !ok1 || !ok2 || r.Pattern == "" || len(r.Pattern) > probe.MaxBlockPat {
			continue
		}
		out = append(out, probe.BlockRule{Event: ev, Op: op, Pattern: r.Pattern})
	}
	return er.Version, out, nil
}

/* cmdPush uploads a recording from disk or stdin. */
func cmdPush(argv []string) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "", "ingest endpoint base URL (or AGENTREC_ENDPOINT)")
	token := fs.String("token", "", "ingest token ar_ing_… (or AGENTREC_TOKEN)")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ep, tok := resolveTarget(*endpoint, *token)

	var body []byte
	var err error
	if fs.NArg() > 0 && fs.Arg(0) != "-" {
		body, err = os.ReadFile(fs.Arg(0))
	} else {
		body, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		return fmt.Errorf("reading recording: %w", err)
	}
	if !json.Valid(body) {
		return errors.New("input is not valid JSON (expected a recording from `agentrec trace --out`)")
	}
	return uploadRecording(ep, tok, body)
}

/* nodeID returns a stable, hashed (non-reversible) identifier for this host, used to meter node-hours. */
func nodeID() string {
	seed := ""
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		seed = strings.TrimSpace(string(b))
	}
	if seed == "" {
		if hn, err := os.Hostname(); err == nil {
			seed = "host:" + hn
		}
	}
	if seed == "" {
		return "unknown"
	}
	h := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(h[:8])
}

/* nodeCred is this node's attestation state; mutated only from the heartbeat goroutine, so no lock. */
type nodeCred struct {
	fp     string /* stable fingerprint (hashed machine id) sent to /v1/nodes/register */
	nodeID string /* server-issued node_… id; empty until registered */
	secret string /* server-issued node_secret; empty => not yet registered */
}

/* registerNode obtains or refreshes this node's attestation credential; idempotent per (workspace, fingerprint). */
func registerNode(endpoint, token, fingerprint string) (nodeID, secret string, err error) {
	hostname, _ := os.Hostname()
	reqBody, _ := json.Marshal(map[string]string{"fingerprint": fingerprint, "hostname": hostname})
	req, err := http.NewRequest(http.MethodPost, endpoint+"/v1/nodes/register", bytes.NewReader(reqBody))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "agentrec-agent/1")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("register failed: HTTP %d", resp.StatusCode)
	}
	var out struct {
		NodeID     string `json:"node_id"`
		NodeSecret string `json:"node_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	if out.NodeID == "" || out.NodeSecret == "" {
		return "", "", errors.New("register response missing node_id/node_secret")
	}
	return out.NodeID, out.NodeSecret, nil
}

/* postHeartbeat sends one attested heartbeat and returns the HTTP status (0 on transport error). */
func postHeartbeat(endpoint, token string, cred *nodeCred) int {
	body, _ := json.Marshal(map[string]string{"node_id": cred.nodeID, "node_secret": cred.secret})
	req, err := http.NewRequest(http.MethodPost, endpoint+"/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "agentrec-agent/1")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

/* sendHeartbeat marks this node active, registering lazily and re-registering once on a 401. */
func sendHeartbeat(endpoint, token string, cred *nodeCred) {
	if endpoint == "" || token == "" {
		return
	}
	if cred.secret == "" {
		id, sec, err := registerNode(endpoint, token, cred.fp)
		if err != nil {
			return
		}
		cred.nodeID, cred.secret = id, sec
	}
	if postHeartbeat(endpoint, token, cred) == http.StatusUnauthorized {
		if id, sec, err := registerNode(endpoint, token, cred.fp); err == nil {
			cred.nodeID, cred.secret = id, sec
			postHeartbeat(endpoint, token, cred)
		}
	}
}

/* startHeartbeat pings /v1/heartbeat immediately and every 5 minutes until stop is closed. */
func startHeartbeat(endpoint, token string, stop <-chan struct{}) {
	endpoint, token = resolveTarget(endpoint, token)
	if endpoint == "" || token == "" {
		return
	}
	cred := &nodeCred{fp: nodeID()}
	go func() {
		sendHeartbeat(endpoint, token, cred)
		tk := time.NewTicker(5 * time.Minute)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				sendHeartbeat(endpoint, token, cred)
			}
		}
	}()
}
