---
name: review-findings
description: How to read rudnik-review's findings and answer a wrong one
---
A finding is one line: its tier (error, warning or info), file:line, the analyser and rule or the model and severity, what it found, then its fingerprint.
Fix each error; a warning or an info is advice, taken where it is right and cheap. One you think wrong, answer in your reply on its own line:
`NOTE-WRONG: <fingerprint>: <why>`
Name the input or the lines that show it, so whoever reads it can judge. A stop is refused at most twice in a row: the third goes through with what is left.
