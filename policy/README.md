# Publisher policy consumer

`publisher-allowlist.json` is the generated publisher consumer from the private
`AtyaLibraries/platform` policy repository. It is not an independently maintained
package catalog.

The snapshot in this revision was copied from
`generated/publisher-allowlist.json` at platform commit
`0110c5e8fd308202224f45834f8b166f6aac15f8`. Its source blob is
`57299552fac7f21d7e0cb1e749575ebe2f81875e`, policy version `1.8.0`, and schema
version `1.0.0`.

The 29 library, tooling and SDK packages of the library monorepo (ADR-14, including the two PostgreSQL adapters)
map to repository `Atya` on `main`; their tags are `<PackageId>/v<SemVer>`. The two template
packages are repositories of their own (ADR-14 amendment) and use the unprefixed `v<SemVer>` tag.

Every entry carries an explicit `symbols` value. `required` (the managed default)
demands a SourceLink-bound `.snupkg`. `none` is declared in platform for packages that
ship no binaries (`Atya.Build.Sdk`, `Atya.Templates.NuGetPackage`,
`Atya.Templates.UiAutomation`); the publisher then verifies, from the package bytes,
that no binary is present and no symbol package exists. The package can never choose
its own value: it comes only from this policy.

The publisher consumes the snapshot at its own immutable workflow revision. This
keeps the production job independent of mutable remote policy and avoids granting
it cross-repository credentials. A policy change is rolled forward by regenerating
the consumer in platform, copying the generated file without manual edits, updating
the provenance values above, and reviewing the publisher change before it reaches
`main`. Until that happens, a newly admitted package fails closed.

Rollback is a revert of the publisher policy/workflow commit. Do not edit individual
mappings in this repository and do not fall back to dispatch-supplied package ids.
