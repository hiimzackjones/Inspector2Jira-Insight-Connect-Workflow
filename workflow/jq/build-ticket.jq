# BuildTicketBody — runs once per finding in the EachFinding loop.
# Input (json_in): the single finding object from ExposureCommandQuery items[].
# Output (json_out): { "summary": <string>, "description": <string> }
def clean($s): ($s // "") | gsub("[\r\n]+"; " ") | gsub("  +"; " ") | gsub("^\\s+|\\s+$"; "");
def dateonly($s): ($s // "") | .[0:10];
def member($arn): ([$arn // "" | scan("[0-9]{12}")] | last) // "unknown";
def totag($t): ($t|index("/")) as $i
  | if $i==null then {key:$t,value:""} else {key:$t[0:$i], value:$t[$i+1:]} end;
def tagval($tags;$k): ($tags | map(select(.key==$k)) | .[0].value | select(.!=null)) // "(untagged)";
def cwe_clean($s): ($s // "") | [splits(", *")] | map(select(test("noinfo")|not)) | join(", ")
  | if .=="" then "n/a" else . end;
def clean_cve($t): ($t // "") | split(" - ")[0];

# split raw affected_hosts (::HOST:: separated) into [{hostip, tags:[{key,value}]}].
# " ::TAGS:: " marks each host boundary; every other token is one tag (also ::HOST::-separated).
def parse_hosts($s):
  ($s // "" | split(" ::HOST:: "))
  | reduce .[] as $t ([];
      if ($t | test("::TAGS::"))
      then ($t | split(" ::TAGS::")) as $p
           | . + [ { hostip: ($p[0]|gsub("^\\s+|\\s+$";"")),
                     tags: (($p[1]//"")|gsub("^\\s+|\\s+$";"")|if .=="" then [] else [.] end) } ]
      else (.[:-1]) + [ (.[-1] | .tags += [ ($t | gsub("^\\s+|\\s+$";"")) ]) ] end )
  | map( {hostip: .hostip, tags: (.tags | map(select(length>0) | totag(.)))} );

(clean_cve(.title)) as $cve
| (parse_hosts(.affected_hosts)) as $hosts
| ([ $hosts[] | .hostip + " — Owner: " + tagval(.tags;"Owner")
                       + ", Repo: "  + tagval(.tags;"Repo")
                       + ", Env: "   + tagval(.tags;"Environment") ] | join("  ;  ")) as $host_block
| ((.accounts_raw // "") | split(" | ")
    | map( (split(" ::ARN:: ")) as $p | $p[0] + " (" + member($p[1]) + ")" ) | join(", ")) as $accts
| (if (.kev_exploited // "") == "true" then true else false end) as $kev
| (((.epss // "0")|tonumber)*100|floor) as $epss_pct
| (((.epss_percentile // "0")|tonumber)*100|floor) as $epss_rank
| {
    summary: ((if $kev then "[KEV] " else "" end)
              + (.severity // "") + " · CVSS " + (.cvss3_score // "n/a")
              + " · Remediation needed for: " + (.title // "")),
    description: (
        (if $kev then "[KEV — ACTIVELY EXPLOITED IN THE WILD] " + clean(.kev_action) + "\n\n" else "" end)
      + "-- RISK --\n"
      + "Severity: " + (.severity // "n/a")
        + "  |  CVSS v3: " + (.cvss3_score // "n/a") + " (" + (.cvss3_severity // "n/a") + ")"
        + "  |  EPSS: " + ($epss_pct|tostring) + "% (" + ($epss_rank|tostring) + "th pct)\n"
      + "Exploit Available: " + (.exploit_available // "n/a")
        + "  |  Fix Available: " + (.fix_available // "n/a") + "\n"
      + "Weakness: " + cwe_clean(.cwe) + "  |  Attack Vector: " + (.attack_vector // "n/a") + "\n\n"
      + "-- DESCRIPTION --\n"
      + clean(.cve_description) + "\n"
      + "Reference: https://nvd.nist.gov/vuln/detail/" + $cve + "\n\n"
      + "-- ENVIRONMENT --\n"
      + "AWS Account(s): " + $accts + "  |  OS: " + (.os // "n/a") + "  |  Region: " + (.regions // "n/a") + "\n"
      + "First Observed: " + dateonly(.first_observed)
        + "  |  Last Seen: " + dateonly(.last_seen)
        + "  |  CVE Published: " + dateonly(.cve_published) + "\n\n"
      + "-- AFFECTED HOSTS --\n"
      + "[AFFECTED-HOSTS] " + $host_block + " [/AFFECTED-HOSTS]"
    )
  }
