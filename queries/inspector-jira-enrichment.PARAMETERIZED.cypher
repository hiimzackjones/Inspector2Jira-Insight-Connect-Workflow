MATCH (a:AwsInspectorExposure)<--(a1:Asset)
WHERE a.severity = "{{[$input].[severity]}}"
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
     n.d_weaknesses       AS cwe,
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
ORDER BY first_observed ASC
LIMIT {{[$input].[resultLimit]}}
