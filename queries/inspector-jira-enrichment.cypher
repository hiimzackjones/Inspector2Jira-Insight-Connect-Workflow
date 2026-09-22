// ============================================================================
// Inspector2Jira — Surface Command saved query (enriched)
// ============================================================================
// Paste this into your Surface Command saved query. The InsightConnect workflow
// references it by query_id, so the query text lives HERE (in Surface Command),
// not in the .snpt.
//
// Returns one row per AWS Inspector exposure (CVE), enriched with:
//   • per-host asset data + AWS resource tags (Owner / Repo / Environment)
//   • AWS account name + numeric member-account ID
//   • NIST NVD description, CVSS v3, CWE, attack vector, published date
//   • CISA KEV "actively exploited" flag + required action
//   • FIRST EPSS score + percentile
//
// IMPORTANT
//   • Remove `LIMIT 5` before production, or the workflow only ever sees 5 findings.
//   • The affected_hosts / accounts_raw strings use sentinel delimiters
//     ( ::HOST:: , ::TAGS:: , ::ARN:: ) that the workflow's jq step parses.
//     Do NOT introduce real newlines — they corrupt on the Jira ADF round-trip.
//   • NVD / EPSS join on the CLEAN CVE id: split(a.title, " - ")[0]
//     (Inspector package findings look like "CVE-2021-33430 - numpy").
//   • AWS account: acct.`AwsAccount:Arn` is an ORG account ARN
//     (arn:aws:organizations::<mgmt>:account/<org>/<MEMBER>). The workflow's jq
//     takes the LAST 12-digit group = the member account (NOT the first).
// ============================================================================

MATCH (a:AwsInspectorExposure)<--(a1:Asset)
OPTIONAL MATCH (a1)--(e:AwsEc2Instance)
OPTIONAL MATCH (a1)--(acct:AwsAccount)
OPTIONAL MATCH (n:NistCve2)                 WHERE n.id = split(a.title, " - ")[0]
OPTIONAL MATCH (ep:FirstEpssVulnerability)  WHERE ep.`Vulnerability:id` = split(a.title, " - ")[0]
WITH a, n, ep,
     collect(DISTINCT
        a1.hostnames[0] + " (" + a1.ips[0] + ")"
        + " ::TAGS:: " + coalesce(e.flat_tags, "")
     ) AS host_lines,
     collect(DISTINCT coalesce(a1.cloud_account, "unknown") + " ::ARN:: " + coalesce(acct.`AwsAccount:Arn`, "")) AS accounts,
     collect(DISTINCT coalesce(a1.os_family, "unknown")) AS os_list,
     collect(DISTINCT coalesce(a1.location,  "unknown")) AS region_list,
     min(a1.first_seen) AS first_observed,
     max(a1.last_seen)  AS last_seen
RETURN
     a.title              AS title,
     a.severity           AS severity,
     a.type               AS type,
     a.fixAvailable       AS fix_available,
     a.exploitAvailable   AS exploit_available,
     n.description        AS cve_description,
     n.cvss_3_basescore   AS cvss3_score,
     n.cvss_3_basesev     AS cvss3_severity,
     n.d_weaknesses       AS cwe,              // NOTE: d_weaknesses, NOT weaknesses (that one is empty)
     n.attack_vector      AS attack_vector,
     n.is_exploited       AS kev_exploited,
     n.cisaRequiredAction AS kev_action,
     n.published          AS cve_published,
     ep.`FirstEpssVulnerability:epss`       AS epss,
     ep.`FirstEpssVulnerability:percentile` AS epss_percentile,
     join(host_lines, " ::HOST:: ") AS affected_hosts,
     join(accounts, " | ")          AS accounts_raw,
     join(os_list, ", ")            AS os,
     join(region_list, ", ")        AS regions,
     first_observed       AS first_observed,
     last_seen            AS last_seen
LIMIT 5
