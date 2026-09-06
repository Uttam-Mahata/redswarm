# Report Format

The Report node compiles operator-approved `confirmed` findings into a
structured document. Two outputs: a machine-readable JSON artifact (for
tooling/ticketing integration) and a human-readable Markdown/PDF summary.

## JSON artifact

```json
{
  "engagement_id": "string",
  "target_domain": "string",
  "scope": { "...": "as granted, for the record" },
  "started_at": "iso8601",
  "completed_at": "iso8601",
  "findings": [
    {
      "id": "string",
      "subdomain": "string",
      "category": "misconfigured_header | ssrf | xss | ...",
      "severity": "low | medium | high | critical",
      "description": "plain-language summary",
      "evidence": {
        "request": "...",
        "response": "...",
        "tool_output": "..."
      },
      "cve_refs": ["CVE-xxxx-xxxx"],
      "confirmed_by": "validator node id",
      "approved_by": "operator id",
      "approved_at": "iso8601",
      "remediation": "suggested fix"
    }
  ],
  "excluded_summary": {
    "false_positive_count": 0,
    "out_of_scope_dropped_count": 0
  },
  "audit_log_ref": "pointer to full audit log export"
}
```

## Human-readable summary

Sections, in order:

1. **Executive summary** — scope, duration, count of findings by
   severity, one-paragraph overall risk statement.
2. **Methodology** — what recon and validation steps were run, explicitly
   noting the non-destructive validation policy (this is often needed
   for the client to trust the report).
3. **Findings**, ordered by severity, each with: description, affected
   asset, evidence (redacted where evidence contains sensitive data),
   remediation guidance, CVE references if applicable.
4. **Out-of-scope / excluded notes** — anything discovered but dropped
   for being outside the scope grant, so the client knows the boundary
   was respected rather than assuming it wasn't looked at.
5. **Appendix: audit log excerpt** — enough of the audit trail to show
   how each finding was reached, full log available as a separate export.

## Evidence redaction

Any evidence containing what looks like real credentials, PII, or
session tokens is redacted (masked, not deleted — the masked marker
notes what was found) before the report leaves the pipeline. Full
unredacted evidence stays only in the Agent's private audit log, not in
the distributed report.
