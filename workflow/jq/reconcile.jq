# Reconcile — replaces the JQComparison step.
# Input (json_in): { issues: <matched Jira tickets w/ .key & .description>,
#                    fromASM: <this finding's affected_hosts, raw ::HOST:: string from the query> }
# Keys on "host (ip)" ONLY; tag changes never trigger false remediation.
def totag($t): ($t|index("/")) as $i | if $i==null then {key:$t,value:""} else {key:$t[0:$i],value:$t[$i+1:]} end;
def tagval($tags;$k): ($tags|map(select(.key==$k))|.[0].value|select(.!=null)) // "(untagged)";

def query_map($fromASM):
  ($fromASM // "" | split(" ::HOST:: "))
  | reduce .[] as $t ([];
      if ($t|test("::TAGS::"))
      then ($t|split(" ::TAGS::")) as $p
           | . + [ {key:($p[0]|gsub("^\\s+|\\s+$";"")),
                    tags:(($p[1]//"")|gsub("^\\s+|\\s+$";"")|if .=="" then [] else [.] end)} ]
      else (.[:-1]) + [ (.[-1]|.tags += [ ($t|gsub("^\\s+|\\s+$";"")) ]) ] end )
  | map({key:.key, tags:(.tags|map(select(length>0)|totag(.)))});

def ticket_lines($desc):
  ($desc // "")
  | if test("\\[AFFECTED-HOSTS\\]")
    then (split("[AFFECTED-HOSTS]")[1] | split("[/AFFECTED-HOSTS]")[0])
         | gsub("\\\\n";" ")
         | split("  ;  ") | map(gsub("^\\s+|\\s+$";"")) | map(select(length>0))
    else [] end;
def line_key($line): $line | split(" — ")[0] | gsub("^\\s+|\\s+$";"");
def line_owner($line): ($line | capture("Owner: (?<o>[^,]+)").o) // "unknown";
def splice($desc; $newlines):
  ($desc | split("[AFFECTED-HOSTS]")[0]) as $pre
  | ($desc | split("[/AFFECTED-HOSTS]")[1] // "") as $post
  | $pre + "[AFFECTED-HOSTS] " + ($newlines | join("  ;  ")) + " [/AFFECTED-HOSTS]" + $post;

(query_map(.fromASM)) as $q
| ([$q[].key]) as $qkeys
| ([.issues[] | ticket_lines(.description) | .[] | line_key(.)]) as $all_ticket_keys
| ($qkeys - $all_ticket_keys) as $added_keys
| {
    added: $added_keys,
    added_count: ($added_keys|length),
    added_lines: [ $q[] | select(.key as $k | ($added_keys|index($k)))
                   | .key + " — Owner: " + tagval(.tags;"Owner")
                          + ", Repo: " + tagval(.tags;"Repo")
                          + ", Env: " + tagval(.tags;"Environment") ],
    ticket_updates: [ .issues[] | . as $iss
        | (ticket_lines($iss.description)) as $lines
        | ($lines | map(select(line_key(.) as $k | ($qkeys|index($k)))))       as $survivors
        | ($lines | map(select(line_key(.) as $k | ($qkeys|index($k))|not)))   as $removed_lines
        | select(($removed_lines|length) > 0)
        | { ticket_id: $iss.key,
            removed_hosts: ($removed_lines | map(line_key(.))),
            new_description: splice($iss.description; $survivors),
            removed_comment: ("Remediation update — the following host(s) no longer appear in the latest AWS Inspector scan and have been removed from this ticket:\n\n"
              + ($removed_lines | map(" • " + line_key(.) + " — Owner: " + line_owner(.)) | join("\n"))
              + "\n\n" + (($removed_lines|length)|tostring) + " host(s) removed · "
              + (($survivors|length)|tostring) + " still affected.") }
      ]
  }
