(.findings | map(.title)) as $titles
| {
    stale_tickets: [ .tickets[]
      | . as $t
      | ($t.summary // "") as $s
      | ($t.description // "") as $d
      | ($titles | any(. as $x | $s | contains($x))) as $title_present
      | (if ($d | test("\\[AFFECTED-HOSTS\\]"))
         then ( ($d | split("[AFFECTED-HOSTS]")[1] | split("[/AFFECTED-HOSTS]")[0])
                | gsub("\\\\n";" ") | split("  ;  ") | map(gsub("^\\s+|\\s+$";"")) | map(select(length>0)) | length )
         else -1 end) as $hostcount
      | if ($title_present | not)
          then ($t + {close_reason: "Closed automatically — this finding no longer appears in the latest Surface Command scan."})
        elif ($hostcount == 0)
          then ($t + {close_reason: "Closed automatically — all affected hosts for this finding have been remediated."})
        else empty end
    ]
  }
