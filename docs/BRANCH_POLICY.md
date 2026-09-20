# Main-only development and release-track retirement

The maintainer requested that needed work be integrated and all branches other than `main` be retired. This document
records that repository-policy decision; it is not a Burp smoke result, a version authorization, or a release approval.

## Integration versus release

- `main` is the only long-lived branch and the required final state after a work item. Temporary PR branches must be
  removed after verified integration; merged-PR automatic deletion stays enabled.
- Integration requires review, regression tests, clean packaging/SBOM, and successful read-only CI, including the
  existing conformance and contract gates. Conflict resolution must preserve newer main-line changes.
- Native Burp validation remains distinct from fixture-based tests. A development change may be integrated with native
  checks explicitly recorded as `NOT RUN`; it must not be represented as release-ready. This supersedes the former
  blanket pre-merge manual-smoke requirement, not any release tag, evidence, vulnerability, or publication gate.
- Exact-byte Community/Professional smoke, signatures, source identity, dependency integrity, observation, provenance,
  immutable assets, and all other requirements in [RELEASING.md](RELEASING.md) still gate releases.
- Do not create a release/test tag or upload a substitute release artifact to work around a failed gate. CI bundles are
  development test artifacts only. Report branch integration and release readiness separately.

## Retired v4.11 promotion track

The separate `release/v4.11` stable-promotion plan is retired, not merged with advancing v4.12 code and not declared to
have passed. Its exact historical head is **`a28dd5b4b7f14dafa3c846f02e67d49594b0bf48`**, already an ancestor of protected
`main`. The [historical release policy](https://github.com/sehoon123/mcp-server/blob/a28dd5b4b7f14dafa3c846f02e67d49594b0bf48/docs/RELEASING.md)
and original evidence identities remain available at that immutable commit. Published/draft tags, assets, checksums,
attestations, and the public RC7 are not changed or reinterpreted.

Retirement procedure:

1. Inventory all branch tips, open PRs, tags, and rulesets; confirm no release workflow is running or queued.
2. Integrate needed topic changes only after checks pass. Preserve a SHA inventory and recoverable bundle for topic
   commits not directly reachable from `main`; verify restoration instead of assuming a backup is usable.
3. Verify the frozen release head still equals the SHA above and is reachable from protected `main`. Preserve its
   ruleset snapshot and a recovery bundle before deleting that exact ref using maintainer-authorized administration.
4. Leave main/tag protection unchanged. Retain ruleset `20183424` for the exact retired ref, add a creation prohibition,
   and remove its administrator bypass so accidental recreation cannot reactivate the old promotion path.
5. Prune local tracking refs and obsolete local branches; verify that both local heads and remote heads contain only
   `main`, no PR work was lost, and every pre-existing tag is unchanged. Record the result on the consolidation PR.

The legacy v4.11-only workflow contracts remain checked in to interpret historical evidence. They are **not migrated to
main by relabeling a trust ref**. Deleting the frozen branch makes its exact ancestry/dispatch requirements unavailable;
the current identity gate also continues to reject unpinned successor identities and versions above v4.11.0. A future
main-based release therefore needs a separately reviewed successor identity/pin migration and fresh candidate evidence.
There is no automatic promotion of old RC7 evidence into a v4.12 release and no fabricated v4.11 stable predecessor.

## Consolidated work

PR #69 carries the validated endpoint, bounded client configuration, and recent-audit fixes. The useful fail-closed
classification work from PR #56 is ported onto that current tree, retaining the newer exhaustive `NativeToolStatus`
classification rather than accepting the obsolete side of its conflict. Exact status-count/outcome tests protect the
wire contract; no tool, request/execution capability, approval bypass, schema, dependency, or proxy pin is added.
