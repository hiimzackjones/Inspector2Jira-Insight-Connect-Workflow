.title as $t
| { issues:
    [ .issues[]
      | select(
          ( (.summary // "")
            | sub("^.*Remediation needed for: "; "")
            | sub(" \\(new hosts\\)$"; "")
          ) == $t
        )
    ]
  }
