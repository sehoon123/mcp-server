# Project completion preference

The maintainer's standing request is to finish implementation work with verification, a signed commit and push,
a signed version tag, and a downloadable JAR upload—not merely an uncommitted local build. Preserve this preference
across sessions; report the commit, tag, and download URL when those steps succeed.

Keep the release/security gates in `docs/RELEASING.md` intact. A failed or missing pre-tag check blocks tagging;
missing publication evidence blocks publication. Never bypass a gate by renaming a test release or manually publishing
an incomplete draft. If blocked, complete the permitted commit/CI artifact steps, report the exact remaining blocker,
and distinguish uploaded CI test artifacts from a tagged release. Never move existing tags or replace prior assets.
Do not describe a partial result as completed while required verification, publication, or branch cleanup is blocked.

# Single-main-branch completion preference

The maintainer requests a final state with only `main`, both locally and on `origin`. Review outstanding branches,
merge needed changes into `main` after their required checks, and remove merged, superseded, or unnecessary topic
branches. Temporary work branches are not the final deliverable. Keep automatic deletion of merged PR branches enabled.

Before deleting a branch, verify its tip and disposition: ancestry or an exact merged-PR head for integrated work,
or an explicit review of superseded/unneeded changes. Preserve a SHA inventory and a recoverable Git bundle for
retired commits not reachable from `main`; do not discard unreviewed changes or a live PR just to reduce branch count.
Recheck branch tips before deletion, prune remote-tracking refs, and report the actual remaining branches.

Follow `docs/BRANCH_POLICY.md` for main-only integration and retirement of the historical v4.11 promotion track.
Development integration requires review and passing automated/CI checks; explicitly record unavailable native Burp
checks as NOT RUN. Integration does not satisfy the mandatory real-Burp release/publication evidence. Keep main/tag
protections and every release gate intact; never invent smoke results or reinterpret retired evidence to authorize a
release. Report successful branch consolidation separately from any remaining release blockers.
