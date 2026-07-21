[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'scripts/PublisherSecurity.psm1') -Force
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression

$script:Passed = 0
$script:Failed = 0

function Test-Case([string] $Name, [scriptblock] $Body) {
    try {
        & $Body
        $script:Passed++
        Write-Host "PASS $Name"
    }
    catch {
        $script:Failed++
        Write-Host "FAIL $Name"
        Write-Host $_.Exception.Message
    }
}

function Assert-Equal($Expected, $Actual) {
    if ($Expected -cne $Actual) { throw "Expected '$Expected'; got '$Actual'." }
}

function Assert-True([bool] $Value, [string] $Message) {
    if (-not $Value) { throw $Message }
}

function Assert-Throws([string] $ExpectedMessage, [scriptblock] $Body) {
    try { & $Body }
    catch {
        Assert-Equal $ExpectedMessage $_.Exception.Message
        return
    }
    throw 'Expected the operation to fail closed.'
}

function New-TestPackage {
    param(
        [Parameter(Mandatory)][string] $Path,
        [string] $PackageId = 'Atya.Foundation.Guards',
        [string] $RepositoryUrl = 'https://github.com/AtyaLibraries/Guards',
        [int] $NuspecCount = 1,
        [switch] $MalformedXml,
        [switch] $MissingId,
        [switch] $DuplicateId,
        [switch] $MissingRepository,
        [switch] $DuplicateMetadata,
        [switch] $ForeignIdentityNamespace,
        [string] $DefaultNamespace = ''
    )

    $archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($index in 1..$NuspecCount) {
            $entry = $archive.CreateEntry("package$index.nuspec")
            $stream = $entry.Open()
            try {
                $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
                try {
                    if ($MalformedXml) {
                        $writer.Write('<package><metadata>')
                    }
                    else {
                        $escapedId = [Security.SecurityElement]::Escape($PackageId)
                        $escapedUrl = [Security.SecurityElement]::Escape($RepositoryUrl)
                        $prefix = if ($ForeignIdentityNamespace) { 'foreign:' } else { '' }
                        $foreignNamespace = if ($ForeignIdentityNamespace) { ' xmlns:foreign="urn:foreign"' } else { '' }
                        $defaultNamespaceAttribute = if ($DefaultNamespace) { " xmlns=`"$DefaultNamespace`"" } else { '' }
                        $id = if ($MissingId) { '' } elseif ($DuplicateId) { "<id>$escapedId</id><id>$escapedId</id>" } else { "<$($prefix)id>$escapedId</$($prefix)id>" }
                        $repository = if ($MissingRepository) { '' } else { "<$($prefix)repository type=`"git`" url=`"$escapedUrl`" />" }
                        $metadata = "<metadata>$id<version>1.2.3</version>$repository</metadata>"
                        if ($DuplicateMetadata) { $metadata += $metadata }
                        $writer.Write("<?xml version=`"1.0`"?><package$defaultNamespaceAttribute$foreignNamespace>$metadata</package>")
                    }
                }
                finally { $writer.Dispose() }
            }
            finally { $stream.Dispose() }
        }
    }
    finally { $archive.Dispose() }
}

function New-PolicyFile([string] $Path, [object[]] $Packages, [string] $Schema = '1.0.0', [string] $Version = '1.5.1') {
    $json = [ordered]@{ schemaVersion = $Schema; policyVersion = $Version; packages = $Packages } |
        ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ("publisher-security-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $allowlistPath = Join-Path $root 'policy/publisher-allowlist.json'
    $invalidRepository = 'The source repository identity is not an approved AtyaLibraries owner/name value.'
    $invalidRef = 'The source ref is not an immutable release tag.'
    $invalidVersion = 'The release tag does not contain a supported semantic version.'
    $invalidPath = 'path is not a safe repository-relative path.'
    $invalidUrl = 'Package repository metadata is not a supported canonical GitHub URL.'

    Test-Case 'canonical request passes' {
        Assert-Equal 'AtyaLibraries/Guards' (ConvertTo-CanonicalRepository 'AtyaLibraries/Guards')
        $release = ConvertTo-CanonicalReleaseRef 'v1.2.3-preview.1'
        Assert-Equal 'refs/tags/v1.2.3-preview.1' $release.Ref
        Assert-Equal '1.2.3-preview.1' $release.Version
        Assert-Equal 'src/Guards.csproj' (ConvertTo-SafeRelativePath 'src/Guards.csproj' 'project')
    }

    foreach ($repository in @('Other/Guards', 'atyalibraries/Guards', 'AtyaLibraries/Guards.git', 'AtyaLibraries/../Guards', 'AtyaLibraries/Guards/extra')) {
        Test-Case "unsafe repository fails: $repository" { Assert-Throws $invalidRepository { ConvertTo-CanonicalRepository $repository } }
    }
    foreach ($ref in @('main', 'refs/heads/v1.2.3', 'V1.2.3')) {
        Test-Case "unsafe ref fails: $ref" { Assert-Throws $invalidRef { ConvertTo-CanonicalReleaseRef $ref } }
    }
    foreach ($ref in @('v1.2', 'v1.2.3+metadata', 'v1.2.3/other', 'v01.2.3', 'v1.02.3', 'v1.2.03', 'v1.2.3-01')) {
        Test-Case "invalid semantic version fails: $ref" { Assert-Throws $invalidVersion { ConvertTo-CanonicalReleaseRef $ref } }
    }
    foreach ($path in @('../secret', '/tmp/file', 'src\file.csproj', './src/file.csproj', 'src/$file.csproj', 'src//file.csproj', 'src/file.csproj/')) {
        Test-Case "unsafe path fails: $path" { Assert-Throws $invalidPath { ConvertTo-SafeRelativePath $path 'path' } }
    }

    $validPackage = Join-Path $temp 'valid.nupkg'
    New-TestPackage -Path $validPackage
    Test-Case 'authorized derived PackageId and repository pass' {
        $identity = Read-PackageIdentity $validPackage
        $policy = Read-PublisherAllowlist $allowlistPath
        $result = Test-PackageAuthorization $identity 'AtyaLibraries/Guards' $policy
        Assert-Equal 'Atya.Foundation.Guards' $result.PackageId
        Assert-Equal '1.5.1' $result.PolicyVersion
    }
    Test-Case 'optional canonical dot-git repository URL passes' {
        Assert-Equal 'AtyaLibraries/Guards' (ConvertFrom-PackageRepositoryUrl 'https://github.com/AtyaLibraries/Guards.git/')
    }

    $namespacedPackage = Join-Path $temp 'namespaced.nupkg'
    New-TestPackage -Path $namespacedPackage -DefaultNamespace 'http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd'
    Test-Case 'standard namespaced nuspec passes' {
        Assert-Equal 'Atya.Foundation.Guards' (Read-PackageIdentity $namespacedPackage).PackageId
    }

    $unknownPackage = Join-Path $temp 'unknown.nupkg'
    New-TestPackage -Path $unknownPackage -PackageId 'Atya.Unknown.Package' -RepositoryUrl 'https://github.com/AtyaLibraries/Guards'
    Test-Case 'unknown PackageId fails' {
        Assert-Throws 'The derived package id is not uniquely authorized by publisher policy.' { Test-PackageAuthorization (Read-PackageIdentity $unknownPackage) 'AtyaLibraries/Guards' (Read-PublisherAllowlist $allowlistPath) }
    }

    $wrongProvenance = Join-Path $temp 'wrong-provenance.nupkg'
    New-TestPackage -Path $wrongProvenance -RepositoryUrl 'https://github.com/AtyaLibraries/Results'
    Test-Case 'PackageId-to-repository policy mismatch fails' {
        Assert-Throws 'The derived package id is not authorized for the requested repository.' { Test-PackageAuthorization (Read-PackageIdentity $wrongProvenance) 'AtyaLibraries/Results' (Read-PublisherAllowlist $allowlistPath) }
    }
    Test-Case 'nuspec provenance mismatch fails' {
        Assert-Throws 'Package repository provenance does not match the requested repository.' { Test-PackageAuthorization (Read-PackageIdentity $wrongProvenance) 'AtyaLibraries/Guards' (Read-PublisherAllowlist $allowlistPath) }
    }

    foreach ($case in @(
        @{ Name = 'repository owner case'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/atyalibraries/Guards' },
        @{ Name = 'PackageId case'; Id = 'atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Guards' },
        @{ Name = 'repository query'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Guards?ref=main' },
        @{ Name = 'repository fragment'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Guards#readme' },
        @{ Name = 'repository userinfo'; Id = 'Atya.Foundation.Guards'; Url = 'https://user@github.com/AtyaLibraries/Guards' },
        @{ Name = 'repository port'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com:444/AtyaLibraries/Guards' },
        @{ Name = 'alternate host'; Id = 'Atya.Foundation.Guards'; Url = 'https://www.github.com/AtyaLibraries/Guards' },
        @{ Name = 'encoded repository'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/%47uards' },
        @{ Name = 'encoded slash'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries%2FGuards' },
        @{ Name = 'encoded backslash'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries%5CGuards' },
        @{ Name = 'dot segment repository'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Other/../Guards' },
        @{ Name = 'double slash repository'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries//Guards' },
        @{ Name = 'repository prefix'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/prefix/AtyaLibraries/Guards' },
        @{ Name = 'repository suffix'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries/Guards/extra' },
        @{ Name = 'repository backslash'; Id = 'Atya.Foundation.Guards'; Url = 'https://github.com/AtyaLibraries\Guards' }
    )) {
        $path = Join-Path $temp (($case.Name -replace ' ', '-') + '.nupkg')
        New-TestPackage -Path $path -PackageId $case.Id -RepositoryUrl $case.Url
        $expected = if ($case.Name -eq 'PackageId case') { 'The package id is missing or malformed.' } else { $invalidUrl }
        Test-Case "$($case.Name) normalization fails closed" { Assert-Throws $expected { Read-PackageIdentity $path } }
    }

    $repositoryCase = Join-Path $temp 'repository-slug-case.nupkg'
    New-TestPackage -Path $repositoryCase -RepositoryUrl 'https://github.com/AtyaLibraries/guards'
    Test-Case 'repository slug case normalization fails closed' {
        Assert-Throws 'Package repository provenance does not match the requested repository.' { Test-PackageAuthorization (Read-PackageIdentity $repositoryCase) 'AtyaLibraries/Guards' (Read-PublisherAllowlist $allowlistPath) }
    }

    $missingNuspec = Join-Path $temp 'missing-nuspec.nupkg'
    $emptyArchive = [IO.Compression.ZipFile]::Open($missingNuspec, [IO.Compression.ZipArchiveMode]::Create)
    $emptyArchive.Dispose()
    Test-Case 'missing nuspec fails' { Assert-Throws 'The package must contain exactly one nuspec.' { Read-PackageIdentity $missingNuspec } }

    $duplicateNuspec = Join-Path $temp 'duplicate-nuspec.nupkg'
    New-TestPackage -Path $duplicateNuspec -NuspecCount 2
    Test-Case 'duplicate nuspec fails' { Assert-Throws 'The package must contain exactly one nuspec.' { Read-PackageIdentity $duplicateNuspec } }

    $malformedArchive = Join-Path $temp 'malformed-archive.nupkg'
    [IO.File]::WriteAllBytes($malformedArchive, [byte[]] (1, 2, 3, 4))
    Test-Case 'malformed ZIP fails with sanitized reason' { Assert-Throws 'The package artifact is not a valid ZIP archive.' { Read-PackageIdentity $malformedArchive } }

    $malformed = Join-Path $temp 'malformed.nupkg'
    New-TestPackage -Path $malformed -MalformedXml
    Test-Case 'malformed nuspec fails' { Assert-Throws 'The package nuspec is not valid safe XML.' { Read-PackageIdentity $malformed } }

    $foreignNamespace = Join-Path $temp 'foreign-namespace.nupkg'
    New-TestPackage -Path $foreignNamespace -ForeignIdentityNamespace
    Test-Case 'foreign-namespace identity elements fail' { Assert-Throws 'The package nuspec must contain exactly one id and repository element.' { Read-PackageIdentity $foreignNamespace } }

    $duplicateMetadata = Join-Path $temp 'duplicate-metadata.nupkg'
    New-TestPackage -Path $duplicateMetadata -DuplicateMetadata
    Test-Case 'duplicate metadata elements fail' { Assert-Throws 'The package nuspec must contain exactly one metadata element.' { Read-PackageIdentity $duplicateMetadata } }

    $duplicateId = Join-Path $temp 'duplicate-id.nupkg'
    New-TestPackage -Path $duplicateId -DuplicateId
    Test-Case 'duplicate package id metadata fails' { Assert-Throws 'The package nuspec must contain exactly one id and repository element.' { Read-PackageIdentity $duplicateId } }

    $missingId = Join-Path $temp 'missing-id.nupkg'
    New-TestPackage -Path $missingId -MissingId
    Test-Case 'missing package id metadata fails' { Assert-Throws 'The package nuspec must contain exactly one id and repository element.' { Read-PackageIdentity $missingId } }

    $missingRepository = Join-Path $temp 'missing-repository.nupkg'
    New-TestPackage -Path $missingRepository -MissingRepository
    Test-Case 'missing repository metadata fails' { Assert-Throws 'The package nuspec must contain exactly one id and repository element.' { Read-PackageIdentity $missingRepository } }
    Test-Case 'package size boundary fails closed' { Assert-Throws 'The package artifact is missing, empty, oversized, or has an invalid extension.' { Read-PackageIdentity $validPackage -MaximumPackageBytes 1 } }
    Test-Case 'package entry boundary fails closed' { Assert-Throws 'The package contains too many entries.' { Read-PackageIdentity $validPackage -MaximumEntries 0 } }
    Test-Case 'nuspec size boundary fails closed' { Assert-Throws 'The package nuspec is empty or oversized.' { Read-PackageIdentity $validPackage -MaximumNuspecBytes 1 } }

    $badSchema = Join-Path $temp 'bad-schema.json'
    New-PolicyFile $badSchema @([ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Guards'; defaultBranch = 'development' }) '2.0.0'
    Test-Case 'unsupported schema fails' { Assert-Throws 'The publisher allowlist uses an unsupported policy schema or version.' { Read-PublisherAllowlist $badSchema } }

    $badVersion = Join-Path $temp 'bad-version.json'
    New-PolicyFile $badVersion @([ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Guards'; defaultBranch = 'development' }) '1.0.0' '2.0.0'
    Test-Case 'unsupported policy major fails' { Assert-Throws 'The publisher allowlist uses an unsupported policy schema or version.' { Read-PublisherAllowlist $badVersion } }

    $duplicates = Join-Path $temp 'duplicates.json'
    New-PolicyFile $duplicates @(
        [ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Guards'; defaultBranch = 'development' },
        [ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Guards'; defaultBranch = 'development' }
    )
    Test-Case 'duplicate policy ids fail' { Assert-Throws 'The publisher allowlist contains duplicate or ambiguous package metadata.' { Read-PublisherAllowlist $duplicates } }

    Test-Case 'generated policy snapshot is byte-identical to recorded platform blob' {
        $actual = (& git -c "safe.directory=$($root.Replace('\', '/'))" hash-object $allowlistPath).Trim()
        Assert-Equal 'bc4d0fbfe4e752f7db5da17ddf047a1bbb3eb4b8' $actual
    }

    $workflow = (Get-Content -LiteralPath (Join-Path $root '.github/workflows/publish.yml') -Raw) -replace "`r`n", "`n"
    $buildStart = $workflow.IndexOf("  build:`n", [StringComparison]::Ordinal)
    $publishStart = $workflow.IndexOf("  publish:`n", [StringComparison]::Ordinal)
    Assert-True ($buildStart -ge 0 -and $publishStart -gt $buildStart) 'Workflow jobs could not be located.'
    $buildJob = $workflow.Substring($buildStart, $publishStart - $buildStart)
    $publishJob = $workflow.Substring($publishStart)

    Test-Case 'untrusted build job has no publication authority' {
        Assert-True ($buildJob -notmatch 'id-token:\s*write|attestations:\s*write|environment:\s*production|NuGet/login|nuget push|NUGET_API_KEY') 'Build job contains publication authority.'
        Assert-True ($buildJob -match 'permissions:\s*\r?\n\s+contents:\s+read') 'Build job does not declare minimal contents permission.'
    }
    Test-Case 'auto-discovered source paths are canonicalized before job outputs' {
        Assert-True ($buildJob.Contains("ConvertTo-SafeRelativePath -Path `$solution -Name 'solution'")) 'The discovered solution path is not canonicalized.'
        Assert-True ($buildJob.Contains("ConvertTo-SafeRelativePath -Path `$packageProject -Name 'package project'")) 'The discovered package project path is not canonicalized.'
    }
    Test-Case 'privileged job never checks out or builds requested source' {
        Assert-True ($publishJob -notmatch 'build-pack-nuget|working-directory:\s*source|(?m)^\s*repository:\s*\$\{\{\s*needs\.build\.outputs\.repository') 'Publish job can check out or build requested source.'
        Assert-True ($publishJob -match 'repository:\s*AtyaLibraries/publisher') 'Publish job does not use trusted publisher controls.'
    }
    Test-Case 'authorization precedes credential and push steps' {
        $authorize = $publishJob.IndexOf('Validate package identity and authorization', [StringComparison]::Ordinal)
        $login = $publishJob.IndexOf('Log in to NuGet.org', [StringComparison]::Ordinal)
        $push = $publishJob.IndexOf('Push package', [StringComparison]::Ordinal)
        Assert-True ($authorize -ge 0 -and $authorize -lt $login -and $login -lt $push) 'Credential acquisition is not ordered after authorization.'
    }
    Test-Case 'workflow actions use immutable SHA references' {
        $uses = [regex]::Matches($workflow, '(?m)^\s*uses:\s*[^\s]+@([^\s]+)')
        Assert-True ($uses.Count -gt 0) 'No workflow actions were found.'
        foreach ($use in $uses) {
            Assert-True ($use.Groups[1].Value -cmatch '^[0-9a-f]{40}$') "Mutable action reference found: $($use.Value)"
        }
    }
    Test-Case 'workflow carries only one bounded package artifact' {
        Assert-True ($workflow -match 'path:\s*package-artifact/package\.nupkg') 'Artifact upload is not an exact package path.'
        Assert-True ($workflow -match '\$packages\.Count -ne 1') 'Ambiguous package output check is missing.'
        Assert-True ($workflow -match '268435456') 'Package size boundary is missing.'
        Assert-True ($workflow -match 'retention-days:\s*1') 'Artifact retention is not bounded.'
    }
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}

Write-Host "Publisher security tests: $script:Passed passed; $script:Failed failed."
if ($script:Failed -ne 0) { exit 1 }
