# Publisher release runbook

A release is started only by a maintainer running `publish.yml` with
`workflow_dispatch`. No source repository sends a `repository_dispatch` event, and no
long-lived token or personal access token is involved. Pushing a tag does **not**
publish anything.

## Command

```bash
gh workflow run publish.yml --repo AtyaLibraries/publisher \
  -f repository=<owner/repo> -f ref=<tag>
```

Example:

```bash
gh workflow run publish.yml --repo AtyaLibraries/publisher \
  -f repository=AtyaLibraries/Guards -f ref=v1.2.3
```

Follow the run with `gh run list --repo AtyaLibraries/publisher --workflow publish.yml`
and `gh run watch <run-id> --repo AtyaLibraries/publisher`.

## Inputs

| Input | Required | Meaning |
|---|---|---|
| `repository` | yes | Source repository in `owner/name` form. It must be listed in `policy/publisher-allowlist.json`. |
| `ref` | yes | The immutable release tag: `v<semver>` or `<PackageId>/v<semver>`, each optionally written with a leading `refs/tags/`. Branches and other refs are rejected. The tag must point at the commit that gets built. See [Release tags](#release-tags). |
| `solution` | no | Solution path in the source repository. Defaults to the single `.sln` at the repository root. |
| `package_project` | no | Package project path in the source repository. Defaults to the single `.csproj` under `src/`. |
| `global_json` | no | Path to `global.json` in the source repository. Defaults to `global.json`. |

Optional inputs are passed the same way, for example
`-f package_project=./src/Guards/Guards.csproj`. Paths must be relative and stay inside
the source repository.

## Release tags

Two tag forms are accepted:

| Form | Example | Use |
|---|---|---|
| `v<semver>` | `v1.2.3` | A repository that releases exactly one package. |
| `<PackageId>/v<semver>` | `Atya.Foundation.Guards/v1.2.3` | A repository that releases several packages (the library monorepo `AtyaLibraries/Atya`, ADR-14). |

Either form may be passed with a leading `refs/tags/`; the publisher always works with the
canonical `refs/tags/...` form, so a branch can never be mistaken for a tag.

For the prefixed form the prefix is **only a claim**. The trusted job reads the package id
from the built `.nupkg` and requires the prefix to equal it exactly (ordinal,
case-sensitive). The check runs when the release bundle is sealed, again before NuGet
credentials are requested, and again immediately before the push, together with the
existing tag, commit and version binding. A tag for one package therefore can never publish
another package from the same repository.

A prefix must itself look like a package id (`Atya.<Segment>.<Segment>...`). An empty
prefix, extra or doubled slashes, `..`, spaces, a different case and a prefix that is only
part of the package id are all rejected. For a repository that the allowlist maps to more
than one package, the unprefixed `v<semver>` form is refused, because it would not say
which package is being released.

Example (monorepo):

```bash
gh workflow run publish.yml --repo AtyaLibraries/publisher   -f repository=AtyaLibraries/Atya -f ref=Atya.Foundation.Guards/v1.2.3
```

## Content-only packages (`symbols: none`)

These packages ship no binary, so they have no `.snupkg`. They are released with the
same command but need explicit paths, because they do not follow the
`*.sln` + single `src/**/*.csproj` layout. `solution` accepts a project file.
Use exactly these values:

| Package | `repository` | Extra `-f` values |
|---|---|---|
| `Atya.Build.Sdk` | `AtyaLibraries/Atya.Build.Sdk` | `-f solution=src/Atya.Build.Sdk.csproj -f package_project=src/Atya.Build.Sdk.csproj -f global_json=tests/IntegrationConsumer/global.json` |
| `Atya.Templates.NuGetPackage` | `AtyaLibraries/Atya.Templates.NuGetPackage` | `-f solution=Atya.Templates.NuGetPackage.csproj -f package_project=Atya.Templates.NuGetPackage.csproj` |
| `Atya.Templates.UiAutomation` | `AtyaLibraries/Atya.Templates.UiAutomation` | `-f solution=Atya.Templates.UiAutomation.csproj -f package_project=Atya.Templates.UiAutomation.csproj` |

Example:

```bash
gh workflow run publish.yml --repo AtyaLibraries/publisher \
  -f repository=AtyaLibraries/Atya.Build.Sdk -f ref=v<semver> \
  -f solution=src/Atya.Build.Sdk.csproj -f package_project=src/Atya.Build.Sdk.csproj \
  -f global_json=tests/IntegrationConsumer/global.json
```

The policy is not a dispatch input. If the sealed bundle shows a `.snupkg`, or the
package contains a binary, the run fails before any credential is requested.

## Release checklist

1. Make sure CI on `development` is green and the package version is the one you intend
   to ship.
2. Promote `development` to `master` with a pull request and a **merge commit** (not
   squash or rebase), so the release commit is reachable from `master`.
3. Create the tag `v<semver>` on the resulting `master` commit and push it. Never move
   or delete an existing release tag.
4. Run the command above with the repository and the tag.
5. Open the run in GitHub Actions. The `build` job runs first. The `publish` job then
   waits on the `production` environment: review the repository, tag and commit, and
   approve it.
6. After the run succeeds, confirm the package and version on nuget.org and that the
   run produced the sealed release bundle and attestation.

## Failures

- Validation or policy failure (request rejected, repository not allowlisted, tag not
  a release tag, commit mismatch): fix the cause, then start a new run. For a build
  failure in the source repository, correct it and create a new, higher release tag.
- A run that stops after the NuGet push started: follow the forward-only
  partial-publication procedure in
  [RELEASE-ARTIFACT-CONTRACT.md](RELEASE-ARTIFACT-CONTRACT.md). Never overwrite or
  delete a published package, tag, manifest, SBOM or attestation.

See [PUBLISHER-TRUST-BOUNDARY.md](PUBLISHER-TRUST-BOUNDARY.md) for what the workflow
trusts and what it does not.
