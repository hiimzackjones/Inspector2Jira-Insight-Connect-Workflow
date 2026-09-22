# Workflow changes — enrichment build

This documents the exact InsightConnect `.snpt` changes to turn the base sync workflow into
the enriched version. It is written so applying it in the InsightConnect builder is mechanical.

## Confidence / status (read this first)

| Piece | Status | Confidence |
|---|---|---|
| Surface Command query (`queries/inspector-jira-enrichment.cypher`) | validated against live data | **High** — ran repeatedly, all 21 columns populated |
| `workflow/jq/build-ticket.jq` (ticket body) | tested locally with `jq` on real query output | **High** — same jq engine as the plugin |
| `workflow/jq/reconcile.jq` (sync/comment) | tested locally on crafted add/remove/tag-rename scenarios | **High** — same engine |
| `.snpt` graph surgery (new node + edge rewiring) | **NOT done blind** | **Low without the builder** — a wrong edge breaks import |

The two `jq` filters were validated with the same `jq` binary the Rapid7 `jq` plugin runs, so the
transformation logic is trustworthy. The remaining work is InsightConnect *plumbing* (adding one
node, re-pointing a few field references) which must be validated on import in the builder — it is
intentionally left as builder steps below rather than shipped as a blind graph edit that might fail
to import.

## Data-shape contract (why the delimiters exist)

The query emits three flat strings the workflow parses in jq. **No real newlines anywhere** — they
corrupt on the Jira ADF round-trip. Sentinels:

- `affected_hosts`: `host (ip) ::TAGS:: <flat_tags> ::HOST:: host (ip) ::TAGS:: <flat_tags> …`
  - hosts separated by ` ::HOST:: `; each host's tag blob follows ` ::TAGS:: `.
  - `flat_tags` itself is ` ::HOST:: `-separated internally — jq disambiguates because ` ::TAGS:: `
    appears exactly once per host and marks the boundary.
- `accounts_raw`: `alias ::ARN:: <org account ARN> | alias ::ARN:: <arn> …`
- Reconcile **keys on `host (ip)` only** — tag/owner changes never trigger false remediation.

## Node-by-node changes

### 1. `ExposureCommandQuery` (Surface Command · run_query) — external
No `.snpt` change. Update the **saved Surface Command query** (referenced by `query_id`) with
`queries/inspector-jira-enrichment.cypher`. Remove `LIMIT 5` for production.

### 2. NEW node: `BuildTicketBody` (jq · run) — add inside the `EachFinding` loop, before `IssueExists`
- Filter: `workflow/jq/build-ticket.jq`
- Input `json_in`: the current finding item, i.e. `{{[ExposureCommandQuery.$item]}}` (all fields).
- Output `json_out` (string) → follow with a **Type Converter `string_to_object`** so downstream
  steps can read `.summary` and `.description` as real fields. (Same pattern as `ParseAddedRemoved`.)
- Wire: `EachTicket` → `BuildTicketBody` → `TypeConvert` → `FindIssue` (preserve one-in/one-out).

### 3. `CreateNewIssue` (jira · create_issue)
- `summary` → `{{[BuildTicketBody parsed].[summary]}}`
- `description` → `{{[BuildTicketBody parsed].[description]}}`
- keep `labels: [aws-inspector-auto]`, type `Task`.

### 4. `JQComparison` → replace filter with `workflow/jq/reconcile.jq`
- Input stays `{ issues: <enriched_issues>, fromASM: <current finding affected_hosts> }`.
- New output adds `added_lines` and per-ticket `new_description` (splice-preserve: keeps the whole
  ticket body, swaps only the inside of `[AFFECTED-HOSTS]…[/AFFECTED-HOSTS]`) and an enriched
  `removed_comment` (lists each removed `host (ip)` with its Owner + a "N removed · M still affected"
  tally).
- `ExtractHostsFromExistingTicket` is now redundant (reconcile parses ticket hosts itself) — leave it
  in place harmlessly, or remove it and wire `EachMatchedIssue` → `JQComparison` directly.

### 5. `UpdateTicketDescription` (jira · edit_issue)
- `description` → `{{[EachTicketUpdate.$item].[new_description]}}` (unchanged reference; content now
  preserves the enriched header).

### 6. `AddRemovalComment` (jira · comment_issue)
- `comment` → `{{[EachTicketUpdate.$item].[removed_comment]}}` (now includes Owner + tally).

### 7. `CreateAddedHostsTicket` (jira · create_issue)
- Still creates a separate ticket for newly-affected hosts (by design — triggers new-ticket alerting,
  preserves time-to-remediate metrics).
- Minimum: description uses `reconcile.added_lines` wrapped in `[AFFECTED-HOSTS] … [/AFFECTED-HOSTS]`.
- Better (optional): reuse the full `BuildTicketBody` header so the added-hosts ticket is as rich as
  the primary. Deferred refinement.

### 8. Reverse sync (`CheckStaleTickets` → `TransitionStaleTicket`)
- Unchanged logic. Closure comment stays simple: `Finding no longer present in scan; auto-closing.`

## Deferred (pick up during builder integration)
- **Fixed-in-Version** for package vulns: nested in `a.packageVulnerabilityDetails`, which blanks in
  CSV export but should arrive as JSON in the plugin payload. Check the `OutputSample` and, if present,
  extract `fixedInVersion` in `build-ticket.jq`.
- **Emoji vs plain text** for the KEV banner: currently plain `[KEV — ACTIVELY EXPLOITED IN THE WILD]`.
  Swap to 🚨 in one line of `build-ticket.jq` once emoji rendering is confirmed on a live ticket.
- **CVSS vs Inspector severity**: both are shown deliberately (they legitimately differ — Inspector
  adjusts for environment). Decide which drives the summary badge if the customer prefers one.
