def clean($s): ($s // "") | gsub("[\r\n]+"; " ") | gsub("  +"; " ") | gsub("^\\s+|\\s+$"; "");
def dateonly($s): ($s // "") | .[0:10];
def member($arn): ([$arn // "" | scan("[0-9]{12}")] | last) // "unknown";
def totag($t): ($t|index("/")) as $i | if $i==null then {key:$t,value:""} else {key:$t[0:$i],value:$t[$i+1:]} end;
def tagval($tags;$k): ($tags|map(select(.key==$k))|.[0].value|select(.!=null)) // "(untagged)";
def cwe_clean($s): ($s // "") | [splits(", *")] | map(select(test("noinfo")|not)) | join(", ") | if .=="" then "n/a" else . end;
def clean_cve($t): ($t // "") | split(" - ")[0];
def ordinal($n): ($n|tostring) + (if ($n%100>=11 and $n%100<=13) then "th" elif $n%10==1 then "st" elif $n%10==2 then "nd" elif $n%10==3 then "rd" else "th" end);
def query_map($fromASM):
  ($fromASM // "" | split(" ::HOST:: "))
  | reduce .[] as $t ([];
      if ($t|test("::TAGS::"))
      then ($t|split(" ::TAGS::")) as $p
           | . + [ {key:($p[0]|gsub("^\\s+|\\s+$";"")), tags:(($p[1]//"")|gsub("^\\s+|\\s+$";"")|if .=="" then [] else [.] end)} ]
      else (.[:-1]) + [ (.[-1]|.tags += [ ($t|gsub("^\\s+|\\s+$";"")) ]) ] end )
  | map({key:.key, tags:(.tags|map(select(length>0)|totag(.)))});
def qline($h): $h.key + " — Owner: " + tagval($h.tags;"Owner") + ", Repo: " + tagval($h.tags;"Repo") + ", Env: " + tagval($h.tags;"Environment");
def render_desc($f; $lines):
  (clean_cve($f.title)) as $cve
  | ((($f.epss // "0")|tonumber)*100|floor) as $ep
  | ((($f.epss_percentile // "0")|tonumber)*100|floor) as $er
  | (($f.accounts_raw // "") | split(" | ") | map((split(" ::ARN:: ")) as $p | $p[0] + " (" + member($p[1]) + ")") | join(", ")) as $accts
  | (if ($f.kev_exploited // "")=="true" then "[KEV — ACTIVELY EXPLOITED IN THE WILD] " + clean($f.kev_action) + "\n\n" else "" end)
    + "-- RISK --\n"
    + "Severity: " + ($f.severity // "n/a") + "  |  CVSS v3: " + ($f.cvss3_score // "n/a") + " (" + ($f.cvss3_severity // "n/a") + ")  |  EPSS: " + ($ep|tostring) + "% (" + ordinal($er) + " pct)\n"
    + "Exploit Available: " + ($f.exploit_available // "n/a") + "  |  Fix Available: " + ($f.fix_available // "n/a") + "\n"
    + "Weakness: " + cwe_clean($f.cwe) + "  |  Attack Vector: " + ($f.attack_vector // "n/a") + "\n\n"
    + "-- DESCRIPTION --\n" + clean($f.cve_description) + "\nReference: https://nvd.nist.gov/vuln/detail/" + $cve + "\n\n"
    + "-- ENVIRONMENT --\n"
    + "AWS Account(s): " + $accts + "  |  OS: " + ($f.os // "n/a") + "  |  Region: " + ($f.regions // "n/a") + "\n"
    + "First Observed: " + dateonly($f.first_observed) + "  |  Last Seen: " + dateonly($f.last_seen) + "  |  CVE Published: " + dateonly($f.cve_published) + "\n\n"
    + "-- AFFECTED HOSTS --\n[AFFECTED-HOSTS] " + ($lines | join("  ;  ")) + " [/AFFECTED-HOSTS]";
def ticket_lines($desc):
  ($desc // "")
  | if test("\\[AFFECTED-HOSTS\\]")
    then (split("[AFFECTED-HOSTS]")[1] | split("[/AFFECTED-HOSTS]")[0]) | gsub("\\\\n";" ") | split("  ;  ") | map(gsub("^\\s+|\\s+$";"")) | map(select(length>0))
    else [] end;
def lkey($line): $line|split(" — ")[0]|gsub("^\\s+|\\s+$";"");
def lowner($line): ($line|capture("Owner: (?<o>[^,]+)").o) // "unknown";
.finding as $f
| (query_map($f.affected_hosts)) as $q
| ([$q[].key]) as $qkeys
| ([.issues[] | ticket_lines(.description) | .[] | lkey(.)]) as $tkeys
| ($qkeys - $tkeys) as $added_keys
| ($tkeys - $qkeys) as $removed_global
| ([ $q[] | select(.key as $k | ($added_keys|index($k))) | qline(.) ]) as $added_lines
| { added: $added_keys, added_count: ($added_keys|length),
    added_description: render_desc($f; $added_lines),
    removed: $removed_global,
    ticket_updates: [ .issues[] | . as $iss
      | (ticket_lines($iss.description)) as $tl
      | ($tl | map(select(lkey(.) as $k | ($qkeys|index($k)))))     as $surv
      | ($tl | map(select(lkey(.) as $k | ($qkeys|index($k))|not))) as $rem
      | select(($rem|length)>0)
      | ([ $surv[] | lkey(.) as $sk | ($q[] | select(.key==$sk) | qline(.)) ]) as $surv_fresh
      | { ticket_id: $iss.key, new_hosts: ($surv|map(lkey(.))), removed_hosts: ($rem|map(lkey(.))),
          new_description: render_desc($f; $surv_fresh),
          removed_comment: ("Remediation update — the following host(s) no longer appear in the latest AWS Inspector scan and have been removed from this ticket:\n\n"
            + ($rem | map(" • " + lkey(.) + " — Owner: " + lowner(.)) | join("\n"))
            + "\n\n" + (($rem|length)|tostring) + " host(s) removed · " + (($surv_fresh|length)|tostring) + " still affected.") } ] }
