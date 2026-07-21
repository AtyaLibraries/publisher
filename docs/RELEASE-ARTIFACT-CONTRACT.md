# Release artifact contract

## Sealed release unit

A publishable release is one flat directory containing exactly these files:

| File | Required validation |
| --- | --- |
| `package.nupkg` | one safe package; canonical id, SemVer version, repository provenance, and exact source commit |
| `package.snupkg` | matching id/version/provenance/commit; exactly one `SymbolsPackage` type; portable PDB and exact-commit SourceLink validation |
| `package.sbom.cdx.json` | CycloneDX 1.6; identifies the primary filename and SHA-256 |
| `release-manifest.json` | deterministic schema 1.0.0; identity, ref, source commit, policy version, lengths, and SHA-256 for the other three files |

No directory, alternate filename, additional file, link/reparse point, empty file,
or alternate data stream belongs to the unit. Each package is limited to 256 MiB,
the SBOM to 8 MiB, the manifest to 64 KiB, and the sealed aggregate to 520.0625 MiB.
Package archives are additionally bounded to 4,096 entries and 512 MiB expanded
content. These are safety ceilings, not recommended package sizes.

The manifest is UTF-8 without a byte-order mark, newline-terminated, and serialized
in a fixed property and artifact order. Verification reconstructs the canonical
serialization and compares it byte-for-byte as well as checking every recorded
length and SHA-256.

## Publication sequence

The ordering is a security invariant:

1. The unprivileged build stages the exact three input files and transfers them with
   one-day retention.
2. Trusted publisher code validates completeness, package pairing, provenance,
   the tag-resolved commit, Portable PDB SourceLink metadata, SBOM identity,
   policy authorization, and all bounds.
3. Trusted code writes and verifies the deterministic manifest, producing the sealed
   four-file unit.
4. The workflow retains the complete unit for 90 days.
5. One provenance action attests all four exact subject paths.
6. Trusted code verifies the retained/attested bytes again.
7. Only then may the protected job acquire a short-lived NuGet credential.
8. The push step verifies the unit once more immediately before publication with
   the explicitly installed .NET SDK 10.0.301/NuGet client.

Any failure in steps 1–6 prevents credentials and publication. Any failure in the
push-step verification prevents the NuGet command. The build job can never acquire
publication authority.

## NuGet atomicity and partial-push recovery

NuGet publication of a primary package and its colocated `.snupkg` is sequential,
not a remote multi-object transaction. ATYA-018 therefore guarantees that the
complete release unit is validated, retained, and attested before the first
irreversible push; it cannot make the registry transaction atomic.

If the push reports failure or is interrupted after it starts:

1. Stop publication attempts and preserve the workflow run, sealed artifact, and
   attestation. Do not rerun blindly.
2. Determine separately whether the exact package id/version and its symbols are
   visible at the registry, allowing for indexing delay. Compare against the sealed
   manifest and attested hashes; do not trust the command exit status alone.
3. If neither object exists, diagnose the transport or authorization failure and
   rerun only after confirming the same immutable source tag and sealed inputs can be
   reproduced under the normal reviewed workflow.
4. If the primary exists but symbols do not, treat the version as partially
   published. Do not overwrite, delete, or reuse it. Correct the source/configuration,
   advance to a new version and immutable tag, and publish a new complete unit. Follow
   the release incident/revocation process for the incomplete version.
5. If both exist but the workflow result is failed or ambiguous, record the registry
   verification and retained attestation as recovery evidence. Do not republish the
   same version merely to obtain a green run.

Recovery is forward-only. Never force a tag, mutate retained evidence, weaken the
symbol requirement, bypass policy, or expose credentials or private evidence in a
ticket or pull request.

## Compatibility

The required `.snupkg`, SourceLink binding, SBOM, deterministic manifest, pre-push
retention, and pre-push attestation are mandatory for every authorized package.
Projects relying on the former primary-package-only path must adopt the shared Build
SDK symbol defaults before their next release. No per-package publisher exception is
supported.
