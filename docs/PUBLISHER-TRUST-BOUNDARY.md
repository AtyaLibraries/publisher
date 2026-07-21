# Publisher trust boundary

## Security model

The publisher treats the requested source repository, tag, source tree, build, and
every produced artifact as untrusted. The workflow separates them into two jobs:

1. `build` has read-only contents permission. It validates and canonicalizes the
   request, checks out the exact tag, verifies that the tag resolves to `HEAD`, and
   runs the source build. It can transfer only one bounded release bundle containing
   exactly one primary package, one symbol package, and one package SBOM. It has no
   OIDC, attestation, production environment, NuGet credential, or push authority.
2. `publish` has the protected production environment and job-scoped
   OIDC/attestation permissions. It checks out only the immutable publisher revision
   that defined the workflow, then executes trusted publisher validation against the
   transferred bytes. It never checks out or builds requested source.

The trusted job opens packages without extracting them and fails closed on unsafe
archive paths, links, malformed or ambiguous metadata, invalid portable PDBs,
missing SourceLink binding, unexpected files, or any per-file, expanded-content,
entry-count, or aggregate-size boundary violation. Dispatch payloads cannot supply
a package id.

Before `NuGet/login` runs, the job:

- validates the exact canonical repository, immutable SemVer tag, and requested
  version;
- derives matching package id, version, and repository provenance independently
  from both `.nupkg` and `.snupkg` metadata;
- requires a `SymbolsPackage` `.snupkg` whose portable PDB paths correspond to the
  primary assemblies and whose SourceLink data binds to the requested repository;
- verifies the CycloneDX 1.6 SBOM identifies the primary package and its SHA-256;
- authorizes the derived PackageId-to-repository pair against the immutable policy;
- creates a deterministic manifest containing the authorized identity, source ref,
  policy version, lengths, and SHA-256 for all three inputs;
- verifies the resulting four-file sealed bundle, retains it for 90 days, attests
  all four exact files, and verifies the same bytes again.

The push step re-verifies the sealed bundle immediately before invoking NuGet. A
failure anywhere before login makes credential acquisition and publication
unreachable. See [RELEASE-ARTIFACT-CONTRACT.md](RELEASE-ARTIFACT-CONTRACT.md) for
the exact contract and recovery procedure.

Failures use bounded, non-sensitive messages. Package content, tokens, hostile
payload values, and private evidence are not printed.

## Policy provenance and updates

`policy/publisher-allowlist.json` is a byte-identical snapshot of the consumer
generated from `ecosystem/ecosystem.json` in `AtyaLibraries/platform`. The pinned
source commit and blob are recorded in `policy/README.md`. It is read from the
immutable publisher workflow revision, so the production job needs no credential
for the private policy repository and cannot observe a mutable policy change
between build and publish.

This snapshot is generated policy, not a second authority. Package admission and
mapping changes start in platform. After its generator and CI pass, copy the
generated consumer byte-for-byte into publisher, update the provenance note, run
the publisher regression suite, and merge through normal review. A new package is
denied until that rollout completes.

## Compatibility and migration

Callers still provide `repository`, `ref`, and optional solution, package-project,
and global-json paths. They add no PackageId and need no new secret. Release refs
are normalized to fully qualified tags; paths must be safe repository-relative
values; identity and provenance casing must match canonical policy exactly.

ATYA-018 intentionally requires every release build to produce both a portable-PDB
`.snupkg` and the package SBOM emitted by the pinned shared build action. Repositories
that disable symbol production or omit SourceLink are nonconforming and fail before
credentials. There is no publisher exception or compatibility bypass: migrate the
package project to the shared Build SDK defaults, validate locally, and create a new
immutable release tag. The last compatible publisher behavior is the ATYA-016 merge
on `main` (`1ed15efc183e77579f4eded1c3fd43710d4d60d3`).

## Rollback and recovery

Rollback is a normal revert of the isolated publisher commit. Do not rewrite tags,
packages, or historical branches. Reverting to the ATYA-016 behavior removes the
complete-bundle guarantee, so keep publishing stopped while preparing a forward fix.

For a build or pre-push failure, correct the source repository and create a new
immutable release tag according to the release runbook. For a policy denial, verify
the authoritative platform manifest and regenerate its publisher consumer. If the
NuGet push starts but does not complete, follow the forward-only partial-publication
procedure in the artifact contract; never overwrite or delete an immutable package,
symbol package, tag, manifest, SBOM, or attestation.

## Validation

The regression suite creates only local synthetic archives. It cannot request OIDC,
enter the production environment, log in, push, attest, or dispatch the workflow.
Run both supported PowerShell lanes plus sanitization and static checks:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./tests/Test-PublisherSecurity.ps1
pwsh -NoProfile -File ./tests/Test-PublisherSecurity.ps1
pwsh -NoProfile -File ./tests/Test-Sanitization.ps1
git diff --check
```

Also lint `.github/workflows/publish.yml` and require the configured pull-request
checks before review.
