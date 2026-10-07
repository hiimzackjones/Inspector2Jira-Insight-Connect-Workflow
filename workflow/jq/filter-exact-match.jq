.title as $t
| [ .issues[]
    | select(
        ( (.summary // "")
          | sub("^.*Remediation needed for: "; "")
          | sub(" \\(new hosts\\)$"; "")
        ) == $t
      )
  ]
