# Reviewed release-note fragments

Before creating a candidate tag, add `<version>.md` in this directory (for example, `4.8.0-rc.1.md`). The immutable
draft workflow appends the fragment to generated source, change-range, verification, hash, and candidate-status data.

A fragment must contain all of these nonempty sections:

```markdown
## Compatibility

Describe supported Burp editions, Java/client requirements, migration impact, and wire compatibility.

## Security and approval changes

Describe trust-boundary, approval, project-transition, logging, and boundedness changes.

## Known limitations

Describe remaining release blockers, waivers, and operational limits.
```

Do not use placeholders such as `TODO`, `TBD`, or `CHANGEME`. Review the fragment before the candidate tag is signed;
the workflow requires the file to be part of the exact tagged source commit.
