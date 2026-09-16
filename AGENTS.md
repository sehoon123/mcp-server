# Project completion preference

The maintainer's standing request is to finish implementation work with verification, a signed commit and push,
a signed version tag, and a downloadable JAR upload—not merely an uncommitted local build. Preserve this preference
across sessions; report the commit, tag, and download URL when those steps succeed.

Keep the release/security gates in `docs/RELEASING.md` intact. A failed or missing pre-tag check blocks tagging;
missing publication evidence blocks publication. Never bypass a gate by renaming a test release or manually publishing
an incomplete draft. If blocked, complete the permitted commit/CI artifact steps, report the exact remaining blocker,
and distinguish uploaded CI test artifacts from a tagged release. Never move existing tags or replace prior assets.
