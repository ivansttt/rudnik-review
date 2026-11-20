The semgrep rules the review learned (spec 1623), `<lang>/<fingerprint8>.yaml`. The gate runs this folder as semgrep's second
`--config` (spec 1670); this file keeps it in git while it holds no rule, for semgrep stops on a config path that does not exist.
