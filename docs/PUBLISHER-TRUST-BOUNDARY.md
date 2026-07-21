# Publisher trust boundary

## Security model

The publisher treats a requested source repository, its tag, its files, its build,
and its produced package as untrusted until the production job authorizes the
package identity. The workflow separates those concerns into two jobs:

1. `build` has read-only contents permission. It validates and canonicalizes the
   request, checks out the exact tag, verifies that the tag resolves to `HEAD`,
   executes the source build, and uploads exactly one size-bounded `.nupkg` for one
   day. It has no OIDC, attestation, production environment, NuGet credential, or
   push authority.
2. `publish` has the production environment and job-scoped OIDC/attestation
   permissions. It checks out only the publisher revision that defined the
   workflow, downloads the bounded artifact, and executes only trusted publisher
   validation code. It never checks out or builds the requested repository.

The production job opens the package without extracting it. It bounds package
size, entry count, and nuspec size; requires exactly one nuspec, package id, and
repository element; prohibits DTD processing; and derives `PackageId` from that
nuspec. Dispatch payloads cannot supply a package id.

Before `NuGet/login` runs, the job validates all of the following:

- the requested repository is an exact canonical `AtyaLibraries/owner-name` value;
- the request is an exact SemVer release tag and the checked-out commit is the tag;
- package repository metadata is a canonical HTTPS GitHub URL for that repository;
- the generated publisher policy has a supported schema/version and no malformed,
  missing, duplicate, or case-ambiguous entries;
- the derived package id has exactly one policy entry and that entry maps to the
  requested repository.

Failures use bounded, non-sensitive messages. Package content, tokens, and hostile
payload values are not printed.

## Policy provenance and updates

`policy/publisher-allowlist.json` is a byte-identical snapshot of the consumer
generated from `ecosystem/ecosystem.json` in `AtyaLibraries/platform`. The pinned
source commit and blob are recorded in `policy/README.md`. It is deliberately read
from the immutable publisher workflow revision, so the production job needs no
credential for the private policy repository and cannot observe a mutable policy
change between build and publish.

This snapshot is generated policy, not a second authority. Package admission and
mapping changes start in platform. After its generator and CI pass, copy the
generated consumer byte-for-byte into publisher, update the provenance note, run
the publisher regression suite, and merge through normal review. A new package is
denied until that rollout completes.

## Compatibility and migration

Legitimate callers continue to provide `repository`, `ref`, and the optional
solution, package-project, and global-json paths. Release refs are normalized to a
fully qualified tag. Paths now must be safe repository-relative values. Repository,
tag, package id, and repository metadata casing must match canonical policy exactly.

The deliberate breaking behavior is fail-closed handling for branch-like or
ambiguous refs, traversal/absolute paths, case variants, unknown package ids,
mismatched repositories, malformed packages, and packages producing anything other
than one primary `.nupkg`. Callers do not send a PackageId and need no new secret.

## Rollback and recovery

Rollback is a normal revert of the isolated publisher commit. Do not rewrite tags,
packages, or the historical publisher branch. A revert restores the earlier single
job and therefore reopens its trust-boundary risk; use it only to stop publication
while preparing a forward fix, not to resume production publishing.

For a failed build, correct the source repository and create a new immutable release
tag according to the release runbook. For a policy denial, verify the authoritative
platform manifest and regenerate/synchronize its publisher consumer. For a package
that may already have reached NuGet, stop and follow the release-recovery and
revocation procedures; never overwrite an immutable package or tag.

## Validation

The regression suite creates only local synthetic archives and cannot request OIDC,
enter the production environment, log in, push, attest, or trigger this workflow.
Run:

```powershell
pwsh -NoProfile -File ./tests/Test-PublisherSecurity.ps1
pwsh -NoProfile -File ./tests/Test-Sanitization.ps1
git diff --check
```

Also lint `.github/workflows/publish.yml` and confirm the configured pull-request
checks complete before review.
