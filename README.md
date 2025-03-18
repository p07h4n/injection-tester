# Injection Tester

**Disclaimer:**  
This tool is provided for educational and authorized penetration testing purposes only. Use it only on systems you have explicit permission to test. Unauthorized testing may be illegal and unethical.

## Overview

Injection Tester is a Go-based tool designed to automate the testing of various injection vulnerabilities on endpoints. It iterates over a list of injection payloads (including SQL Injection, XSS, SSTI, LDAP, Command Injection, and more) and applies different encoding techniques to bypass WAF rules.

## Features

- Tests for multiple injection types:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Server-Side Template Injection (SSTI)
  - LDAP Injection
  - Command Injection
  - Expression Language (EL) Injection
  - XPath Injection
  - GraphQL Injection
  - SSRF, LFI, RFI
  - NoSQL Injection
  - Mass Assignment

- Encoding techniques used for each payload:
  - Raw
  - URL Encoded
  - Double URL Encoded
  - Base64 Encoded

## Usage

Build and run the tool using the following commands:

```bash
# Build the tool
go build -o injection-tester

# Run the tool
./injection-tester <target_url> <parameter>
