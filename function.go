package hello

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

type webhook struct {
	Type int `json:"type"`
}

func HelloWorld(w http.ResponseWriter, r *http.Request) {
	pubkey_hex, _ := hex.DecodeString("YOUR APPLICATION PUBLIC KEY")
	if !VerifyInteraction(r, ed25519.PublicKey(pubkey_hex)) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	wh := webhook{}

	if err := json.NewDecoder(r.Body).Decode(&wh); err != nil {
		log.Printf("Decode error: %v", err)
		return
	}

	switch wh.Type {
	case 1:
		response := webhook{
			Type: 1,
		}
		json, _ := json.Marshal(response)
		fmt.Fprint(w, string(json))
		return
	}
}

func VerifyInteraction(r *http.Request, key ed25519.PublicKey) bool {
	var msg bytes.Buffer

	signature := r.Header.Get("X-Signature-Ed25519")
	if signature == "" {
		return false
	}

	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}

	if len(sig) != ed25519.SignatureSize {
		return false
	}

	timestamp := r.Header.Get("X-Signature-Timestamp")
	if timestamp == "" {
		return false
	}

	fmt.Printf("signature:%s timestamp:%s", signature, timestamp)

	msg.WriteString(timestamp)

	defer r.Body.Close()
	var body bytes.Buffer

	// at the end of the function, copy the original body back into the request
	defer func() {
		r.Body = ioutil.NopCloser(&body)
	}()

	// copy body into buffers
	_, err = io.Copy(&msg, io.TeeReader(r.Body, &body))
	if err != nil {
		return false
	}

	return ed25519.Verify(key, msg.Bytes(), sig)
}
