#!/usr/bin/env bash
# The action's step (spec 1714): the package from the tree the workflow fetched, so no token and no download from a private release, and
# the version checked is the one the workflow names. The exit is the check's, 1 fails the job.
set -euo pipefail
# another event than pull_request has no base: 2, nothing checked, which 0 must never mean (spec 1730), said on the job (13 Nov 2026)
[[ -n ${GITHUB_BASE_REF:-} ]] || { echo "::error title=rudnik-review::no base to check against: run the action on pull_request"; exit 2; }
[[ ${CACHE_HIT:-} == true ]] || rudnik-review setup   # action.yml installed it; a cache hit restored its tools (spec 2002)
# .rudnik/ is a developer's own record and ignores itself; actions/checkout cleans ignored files first, and this job writes none, so here it
# is only what the change planted, which would drop the very findings this job is the gate for: removed, no developer's record is lost
# (the review, 13 Nov 2026: theirs stay on their own machine)
rm -rf .rudnik
exec rudnik-review check --base "origin/$GITHUB_BASE_REF" --format github
