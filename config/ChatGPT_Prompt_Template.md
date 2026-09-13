# ChatGPT Prompt Template: Bug Bounty Program Rule Extractor

Use this prompt with ChatGPT, Claude, Gemini, or any LLM to convert raw text from any Bug Bounty program (e.g., HackerOne, Bugcrowd, Intigriti) into the standardized YAML format used by the **Autonomous Security Research Agent**.

---

### Copy and Paste the following prompt into ChatGPT:

```text
You are an expert security program policy parser. 
I will provide you with raw text copied from a Bug Bounty program page (or penetration testing rules of engagement). 
Your task is to extract all scope items, boundaries, required headers, rate limits, and rules, and format them into the following strict YAML template.

Strict Instructions:
1. Output ONLY the valid YAML block, enclosed in ```yaml ... ```. No conversational intro or outro.
2. Extract all in-scope targets under `in_scope`. Classify each type as `DOMAIN`, `SUBDOMAIN_WILDCARD`, `IP_CIDR`, `URL_PREFIX`, or `IP_EXACT`.
3. Extract all explicit out-of-scope targets under `out_of_scope` (e.g. third-party integrations, billing, admin portals).
4. Extract any mandatory researcher identification headers under `mandatory_headers` (e.g. `X-HackerOne-Research: <username>`, `User-Agent: <custom>`).
5. Set `rate_limit_rps` based on program limits (default to 5 if not specified).
6. Under `rule_checkboxes`, set boolean flags for standard testing rules according to the program instructions.

Template:
---
program_metadata:
  program_name: "<Program Name>"
  platform: "<HackerOne | Bugcrowd | Intigriti | Private>"
  target_summary: "<Short summary of the program>"
  researcher_handle: "<Your Username or Identifier>"
  authorization_reference: "AUTH-<PROGRAM>-<YEAR>"

network_and_headers:
  rate_limit_rps: 5
  mandatory_headers:
    X-HackerOne-Research: "<Your Username>"
    # Add other required headers if mentioned:
    # User-Agent: "Custom-Agent-v1"

scope_definition:
  in_scope:
    - pattern: "*.example.com"
      type: "SUBDOMAIN_WILDCARD"
      notes: "Main web application and subdomains"
    - pattern: "192.168.10.0/24"
      type: "IP_CIDR"
      notes: "Testing subnet"
  out_of_scope:
    - pattern: "billing.example.com"
      type: "DOMAIN"
      notes: "Out of scope production billing"
    - pattern: "status.example.com"
      type: "DOMAIN"
      notes: "Third party hosted status page"

rule_checkboxes:
  allow_automated_probing: true
  allow_rate_limited_fuzzing: true
  allow_multi_account_testing: true
  enforce_header_injection: true
  prohibit_dos_attacks: true
  prohibit_destructive_writes: true
  prohibit_credential_bruteforce: true
  prohibit_social_engineering: true
  prohibit_third_party_testing: true

Here is the raw text of the program:
[PASTE YOUR RAW PROGRAM RULES HERE]
```
