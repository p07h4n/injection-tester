# Injection Tester

**Disclaimer:**  
This tool is provided for educational and authorized penetration testing purposes only. Use it only on systems you have explicit permission to test. Unauthorized testing may be illegal and unethical.

## Overview

Injection Tester is a Go-based tool designed to automate the testing of various injection vulnerabilities on endpoints. It iterates over a list of injection payloads covering a wide range of attack types such as SQL Injection, XSS, SSTI, LDAP, Command Injection, and more. The tool applies multiple encoding techniques including raw, URL encoding (single, double, and triple), Base64, as well as advanced WAF bypass techniques like hexadecimal encoding, Unicode encoding, and payload obfuscation.

## Features

- **Multi-Injection Testing:**  
  - **SQL Injection**  
  - **Cross-Site Scripting (XSS)**  
  - **Server-Side Template Injection (SSTI)**  
  - **LDAP Injection**  
  - **Command Injection**  
  - **Expression Language (EL) Injection**  
  - **XPath Injection**  
  - **GraphQL Injection**  
  - **Server-Side Request Forgery (SSRF)**  
  - **Local File Inclusion (LFI) & Remote File Inclusion (RFI)**  
  - **NoSQL Injection**  
  - **Mass Assignment**

- **Multiple Encoding Techniques:**  
  - Raw, URL, double URL, and triple URL encoding  
  - Base64 encoding  
  - **Advanced Encodings:**  
    - Hexadecimal encoding  
    - Unicode/UTF-8 encoding

- **Payload Obfuscation & Dynamic Mutation:**  
  - Randomized case and whitespace insertion  
  - Inline comments to disrupt predictable patterns  
  - Automated mutation of payloads to evade sophisticated WAF rules

## Advanced WAF Bypass Techniques

Modern Web Application Firewalls (WAFs) look for predictable patterns in payloads. To counteract this, Injection Tester includes several advanced techniques:

- **Alternative Encoding Schemes:**  
  Convert payloads into hexadecimal or Unicode representations to bypass signature-based filters.

- **Payload Obfuscation:**  
  Mutate payloads by randomizing case, inserting inline comments, or breaking keywords into concatenated strings to evade detection.

- **Multi-layered Encoding:**  
  Combine multiple encoding methods (e.g., Base64 followed by URL encoding or triple URL encoding) to defeat WAF normalization processes.

- **Dynamic Payload Mutation:**  
  Automatically adjust and generate payload variants on the fly based on preset mutation rules, increasing the chance of bypassing advanced WAFs.

## Usage

Build and run the tool using the following commands:

```bash
# Build the tool
go build -o injection-tester

# Run the tool
./injection-tester <target_url> <parameter>
