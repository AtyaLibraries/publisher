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

function New-TestPortablePdbBytes([string] $SourceUrlPrefix) {
    $sourceLinkJson = [Text.Encoding]::UTF8.GetBytes("{`"documents`":{`"/src/*`":`"$SourceUrlPrefix*`"}}")
    if ($sourceLinkJson.Length -lt 128) {
        $blob = [byte[]]::new(2 + $sourceLinkJson.Length)
        $blob[1] = [byte] $sourceLinkJson.Length
        $sourceLinkJson.CopyTo($blob, 2)
    }
    else {
        $blob = [byte[]]::new(3 + $sourceLinkJson.Length)
        $blob[1] = [byte] (0x80 -bor ($sourceLinkJson.Length -shr 8))
        $blob[2] = [byte] ($sourceLinkJson.Length -band 0xFF)
        $sourceLinkJson.CopyTo($blob, 3)
    }
    $pdbStream = [byte[]]::new(32)
    $tableStream = [byte[]]::new(34)
    [BitConverter]::GetBytes([uint64] 1 -shl 55).CopyTo($tableStream, 8)
    [BitConverter]::GetBytes([uint32] 1).CopyTo($tableStream, 24)
    [BitConverter]::GetBytes([uint16] 39).CopyTo($tableStream, 28)
    [BitConverter]::GetBytes([uint16] 1).CopyTo($tableStream, 30)
    [BitConverter]::GetBytes([uint16] 1).CopyTo($tableStream, 32)
    $streams = [ordered]@{
        '#Pdb' = $pdbStream
        '#~' = $tableStream
        '#Strings' = [byte[]] (0)
        '#GUID' = ([Guid] 'CC110556-A091-4D38-9FEC-25AB9A351A6A').ToByteArray()
        '#Blob' = $blob
    }
    $version = [Text.Encoding]::ASCII.GetBytes("PDB v1.0`0`0`0`0")
    $headerLength = 16 + $version.Length + 4
    foreach ($name in $streams.Keys) {
        $nameLength = [Text.Encoding]::ASCII.GetByteCount($name) + 1
        $headerLength += 8 + (($nameLength + 3) -band -4)
    }
    $total = $headerLength + (($streams.Values | ForEach-Object Length | Measure-Object -Sum).Sum)
    $bytes = [byte[]]::new($total)
    [BitConverter]::GetBytes([uint32] 0x424A5342).CopyTo($bytes, 0)
    [BitConverter]::GetBytes([uint16] 1).CopyTo($bytes, 4)
    [BitConverter]::GetBytes([uint16] 1).CopyTo($bytes, 6)
    [BitConverter]::GetBytes([uint32] $version.Length).CopyTo($bytes, 12)
    $version.CopyTo($bytes, 16)
    $directory = 16 + $version.Length
    [BitConverter]::GetBytes([uint16] $streams.Count).CopyTo($bytes, $directory + 2)
    $cursor = $directory + 4
    $dataOffset = $headerLength
    foreach ($name in $streams.Keys) {
        $data = $streams[$name]
        [BitConverter]::GetBytes([uint32] $dataOffset).CopyTo($bytes, $cursor)
        [BitConverter]::GetBytes([uint32] $data.Length).CopyTo($bytes, $cursor + 4)
        $nameBytes = [Text.Encoding]::ASCII.GetBytes($name)
        $nameBytes.CopyTo($bytes, $cursor + 8)
        $cursor += 8 + (($nameBytes.Length + 1 + 3) -band -4)
        $data.CopyTo($bytes, $dataOffset)
        $dataOffset += $data.Length
    }
    return $bytes
}

function New-TestPackage {
    param(
        [Parameter(Mandatory)][string] $Path,
        [string] $PackageId = 'Atya.Foundation.Guards',
        [string] $Version = '1.2.3',
        [string] $RepositoryUrl = 'https://github.com/AtyaLibraries/Guards',
        [string] $SourceCommit = '0123456789012345678901234567890123456789',
        [string] $SourceLinkCommit = '',
        [string] $SourceLinkRepository = 'Guards',
        [int] $NuspecCount = 1,
        [switch] $MalformedXml,
        [switch] $MissingId,
        [switch] $DuplicateId,
        [switch] $MissingRepository,
        [switch] $MissingRepositoryCommit,
        [switch] $DuplicateMetadata,
        [switch] $ForeignIdentityNamespace,
        [string] $DefaultNamespace = '',
        [switch] $SymbolsPackage,
        [switch] $MalformedPortablePdb,
        [switch] $MissingSourceLink,
        [switch] $UnsafeArchivePath,
        [switch] $DuplicateArchivePath,
        [switch] $CaseAmbiguousArchivePath,
        [switch] $DirectoryFileArchiveCollision,
        [switch] $NonCanonicalUnicodeArchivePath
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
                        $commitAttribute = if ($MissingRepositoryCommit) { '' } else { " commit=`"$SourceCommit`"" }
                        $repository = if ($MissingRepository) { '' } else { "<$($prefix)repository type=`"git`" url=`"$escapedUrl`"$commitAttribute />" }
                        $packageType = if ($SymbolsPackage) { '<packageTypes><packageType name="SymbolsPackage" /></packageTypes>' } else { '' }
                        $metadata = "<metadata>$id<version>$Version</version>$packageType$repository</metadata>"
                        if ($DuplicateMetadata) { $metadata += $metadata }
                        $writer.Write("<?xml version=`"1.0`"?><package$defaultNamespaceAttribute$foreignNamespace>$metadata</package>")
                    }
                }
                finally { $writer.Dispose() }
            }
            finally { $stream.Dispose() }
        }

        $contentPath = if ($SymbolsPackage) { 'lib/net10.0/Atya.Foundation.Guards.pdb' } else { 'lib/net10.0/Atya.Foundation.Guards.dll' }
        $contentEntry = $archive.CreateEntry($contentPath)
        $contentStream = $contentEntry.Open()
        try {
            $content = if ($SymbolsPackage) {
                $pdbCommit = if ([string]::IsNullOrEmpty($SourceLinkCommit)) { $SourceCommit } else { $SourceLinkCommit }
                $sourceLink = if ($MissingSourceLink) { 'https://example.invalid/' } else { "https://raw.githubusercontent.com/AtyaLibraries/$SourceLinkRepository/$pdbCommit/" }
                if ($MalformedPortablePdb) {
                    [Text.Encoding]::UTF8.GetBytes("BSJB synthetic portable pdb $sourceLink")
                }
                else { New-TestPortablePdbBytes $sourceLink }
            }
            else { [byte[]] (1, 2, 3, 4) }
            $contentStream.Write($content, 0, $content.Length)
        }
        finally { $contentStream.Dispose() }

        if ($SymbolsPackage) {
            $relationships = $archive.CreateEntry('_rels/.rels')
            $relationshipsStream = $relationships.Open()
            try {
                $relationshipsBytes = [Text.Encoding]::UTF8.GetBytes('<Relationships />')
                $relationshipsStream.Write($relationshipsBytes, 0, $relationshipsBytes.Length)
            }
            finally { $relationshipsStream.Dispose() }
        }

        if ($UnsafeArchivePath) {
            $unsafe = $archive.CreateEntry('../unexpected.txt')
            $unsafe.Open().Dispose()
        }
        if ($DuplicateArchivePath) {
            $duplicate = $archive.CreateEntry($contentPath)
            $duplicate.Open().Dispose()
        }
        if ($CaseAmbiguousArchivePath) {
            $caseVariant = $archive.CreateEntry($contentPath.ToUpperInvariant())
            $caseVariant.Open().Dispose()
        }
        if ($DirectoryFileArchiveCollision) {
            $directoryVariant = $archive.CreateEntry("$contentPath/")
            $directoryVariant.Open().Dispose()
        }
        if ($NonCanonicalUnicodeArchivePath) {
            $unicode = $archive.CreateEntry("lib/e$([char] 0x0301).txt")
            $unicode.Open().Dispose()
        }
    }
    finally { $archive.Dispose() }
}

function New-PolicyFile([string] $Path, [object[]] $Packages, [string] $Schema = '1.0.0', [string] $Version = '1.5.1') {
    $json = [ordered]@{ schemaVersion = $Schema; policyVersion = $Version; packages = $Packages } |
        ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function New-TestSbom([string] $Path, [string] $PackageId, [string] $Version, [string] $PackagePath) {
    $hash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $value = [ordered]@{
        '$schema' = 'http://cyclonedx.org/schema/bom-1.6.schema.json'
        bomFormat = 'CycloneDX'
        specVersion = '1.6'
        version = 1
        serialNumber = 'urn:uuid:00000000-0000-0000-0000-000000000000'
        metadata = [ordered]@{
            component = [ordered]@{ type = 'file'; name = "$PackageId.$Version.nupkg"; version = "sha256:$hash" }
        }
        components = @()
    }
    [IO.File]::WriteAllText($Path, (($value | ConvertTo-Json -Depth 10) + "`n"), [Text.UTF8Encoding]::new($false))
}

function New-TestBundle([string] $Path) {
    New-Item -ItemType Directory -Path $Path | Out-Null
    $primary = Join-Path $Path 'package.nupkg'
    New-TestPackage -Path $primary
    New-TestPackage -Path (Join-Path $Path 'package.snupkg') -SymbolsPackage
    New-TestSbom (Join-Path $Path 'package.sbom.cdx.json') 'Atya.Foundation.Guards' '1.2.3' $primary
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ("publisher-security-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    # Mechanics tests use a single-repository policy fixture (the former generated policy); the
    # generated policy that is actually deployed is checked separately through $policyPath.
    $allowlistPath = Join-Path $PSScriptRoot 'fixtures/single-repository-allowlist.json'
    $policyPath = Join-Path $root 'policy/publisher-allowlist.json'
    $sourceCommit = '0123456789012345678901234567890123456789'
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
    $guardsId = 'Atya.Foundation.Guards'
    Test-Case 'package-prefixed release tags parse in both forms' {
        foreach ($ref in @("$guardsId/v1.2.3-preview.1", "refs/tags/$guardsId/v1.2.3-preview.1")) {
            $release = ConvertTo-CanonicalReleaseRef $ref
            Assert-Equal "refs/tags/$guardsId/v1.2.3-preview.1" $release.Ref
            Assert-Equal '1.2.3-preview.1' $release.Version
            Assert-Equal $guardsId $release.TagPrefix
        }
        Assert-Equal '' (ConvertTo-CanonicalReleaseRef 'v1.2.3').TagPrefix
    }
    $invalidPrefix = 'The release tag prefix is not a valid package id.'
    foreach ($ref in @('/v1.2.3', 'refs/tags//v1.2.3', "$guardsId//v1.2.3", "$guardsId/../v1.2.3", '../Atya.Foundation.Guards/v1.2.3',
            'refs/heads/Atya.Foundation.Guards/v1.2.3', 'a/b/Atya.Foundation.Guards/v1.2.3', "refs/tags/refs/tags/$guardsId/v1.2.3", "$guardsId/V1.2.3", "$guardsId/1.2.3", "$guardsId")) {
        Test-Case "unsafe prefixed ref fails: $ref" { Assert-Throws $invalidRef { ConvertTo-CanonicalReleaseRef $ref } }
    }
    foreach ($ref in @("$guardsId/v1.2.3/extra", "$guardsId/v1.2", "$guardsId/v01.2.3")) {
        Test-Case "prefixed ref with invalid version fails: $ref" { Assert-Throws $invalidVersion { ConvertTo-CanonicalReleaseRef $ref } }
    }
    foreach ($ref in @('Guards/v1.2.3', 'atya.Foundation.Guards/v1.2.3', 'Atya.foundation.Guards/v1.2.3', 'Atya/v1.2.3', 'Atya./v1.2.3', 'Atya.Foundation.Guards./v1.2.3',
            'Atya.Foundation.Guards /v1.2.3', "Atya.Foundation.Guards`n/v1.2.3", 'Atya.Foundation.Gu%61rds/v1.2.3', '..%2FAtya.Foundation.Guards/v1.2.3')) {
        Test-Case "malformed tag prefix fails: $($ref -replace "`n", '<LF>')" { Assert-Throws $invalidPrefix { ConvertTo-CanonicalReleaseRef $ref } }
    }
    Test-Case 'tag prefix must equal the package id exactly' {
        Assert-ReleaseTagPackageBinding "refs/tags/$guardsId/v1.2.3" $guardsId
        Assert-ReleaseTagPackageBinding 'refs/tags/v1.2.3' $guardsId
    }
    $prefixMismatch = 'The release tag prefix does not match the package id inside the package.'
    Test-Case 'prefix for a different package id fails' {
        Assert-Throws $prefixMismatch { Assert-ReleaseTagPackageBinding 'refs/tags/Atya.Foundation.Results/v1.2.3' $guardsId }
    }
    Test-Case 'prefix differing only in case fails' {
        Assert-Throws $prefixMismatch { Assert-ReleaseTagPackageBinding 'refs/tags/Atya.Foundation.GuardS/v1.2.3' $guardsId }
        Assert-Throws $prefixMismatch { Assert-ReleaseTagPackageBinding 'refs/tags/Atya.FOUNDATION.Guards/v1.2.3' $guardsId }
    }
    Test-Case 'prefix that is only a leading part of the package id fails' {
        Assert-Throws $invalidPrefix { Assert-ReleaseTagPackageBinding 'refs/tags/Atya.Foundation/v1.2.3' $guardsId }
        Assert-Throws $prefixMismatch { Assert-ReleaseTagPackageBinding "refs/tags/$guardsId.Extra/v1.2.3" $guardsId }
    }
    Test-Case 'unprefixed tag is refused for a repository that releases several packages' {
        $multi = [pscustomobject]@{ packages = @(
            [pscustomobject]@{ packageId = $guardsId; repository = 'Atya' },
            [pscustomobject]@{ packageId = 'Atya.Foundation.Results'; repository = 'Atya' },
            [pscustomobject]@{ packageId = 'Atya.Other.Single'; repository = 'Single' }) }
        Assert-Throws 'A repository that releases several packages requires a package-prefixed release tag.' {
            Assert-ReleaseTagPackageBinding 'refs/tags/v1.2.3' $guardsId 'Atya' $multi }
        Assert-ReleaseTagPackageBinding 'refs/tags/v1.2.3' 'Atya.Other.Single' 'Single' $multi
        Assert-ReleaseTagPackageBinding "refs/tags/$guardsId/v1.2.3" $guardsId 'Atya' $multi
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
    Test-Case 'foreign-namespace identity elements fail' { Assert-Throws 'The package nuspec must contain exactly one id, version, and repository element.' { Read-PackageIdentity $foreignNamespace } }

    $duplicateMetadata = Join-Path $temp 'duplicate-metadata.nupkg'
    New-TestPackage -Path $duplicateMetadata -DuplicateMetadata
    Test-Case 'duplicate metadata elements fail' { Assert-Throws 'The package nuspec must contain exactly one metadata element.' { Read-PackageIdentity $duplicateMetadata } }

    $duplicateId = Join-Path $temp 'duplicate-id.nupkg'
    New-TestPackage -Path $duplicateId -DuplicateId
    Test-Case 'duplicate package id metadata fails' { Assert-Throws 'The package nuspec must contain exactly one id, version, and repository element.' { Read-PackageIdentity $duplicateId } }

    $missingId = Join-Path $temp 'missing-id.nupkg'
    New-TestPackage -Path $missingId -MissingId
    Test-Case 'missing package id metadata fails' { Assert-Throws 'The package nuspec must contain exactly one id, version, and repository element.' { Read-PackageIdentity $missingId } }

    $missingRepository = Join-Path $temp 'missing-repository.nupkg'
    New-TestPackage -Path $missingRepository -MissingRepository
    Test-Case 'missing repository metadata fails' { Assert-Throws 'The package nuspec must contain exactly one id, version, and repository element.' { Read-PackageIdentity $missingRepository } }

    $missingRepositoryCommit = Join-Path $temp 'missing-repository-commit.nupkg'
    New-TestPackage -Path $missingRepositoryCommit -MissingRepositoryCommit
    Test-Case 'missing repository commit fails' { Assert-Throws 'The package repository commit is missing or malformed.' { Read-PackageIdentity $missingRepositoryCommit } }
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
        $actual = (& git -c "safe.directory=$($root.Replace('\', '/'))" hash-object $policyPath).Trim()
        Assert-Equal '57299552fac7f21d7e0cb1e749575ebe2f81875e' $actual
    }

    $validBundle = Join-Path $temp 'valid-bundle'
    New-TestBundle $validBundle
    Test-Case 'complete authorized release bundle validates and seals' {
        $sealed = New-SealedReleaseBundle $validBundle 'AtyaLibraries/Guards' '1.2.3' 'refs/tags/v1.2.3' $sourceCommit $allowlistPath
        Assert-Equal 'Atya.Foundation.Guards' $sealed.PackageId
        Assert-Equal '1.2.3' $sealed.Version
        Assert-True (Test-Path -LiteralPath (Join-Path $validBundle 'release-manifest.json') -PathType Leaf) 'Release manifest was not generated.'
        Assert-True (Test-SealedReleaseBundle $validBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion) 'Sealed bundle verification failed.'
    }

    # Monorepo release path: one repository, several packages, package-prefixed tags.
    $monoPolicy = Join-Path $temp 'mono-allowlist.json'
    New-PolicyFile $monoPolicy @(
        [ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Atya'; defaultBranch = 'main'; symbols = 'required' },
        [ordered]@{ packageId = 'Atya.Foundation.Results'; repository = 'Atya'; defaultBranch = 'main'; symbols = 'required' })
    function New-MonoBundle([string] $Path) {
        New-Item -ItemType Directory -Path $Path | Out-Null
        $primary = Join-Path $Path 'package.nupkg'
        New-TestPackage -Path $primary -RepositoryUrl 'https://github.com/AtyaLibraries/Atya' -SourceLinkRepository 'Atya'
        New-TestPackage -Path (Join-Path $Path 'package.snupkg') -SymbolsPackage -RepositoryUrl 'https://github.com/AtyaLibraries/Atya' -SourceLinkRepository 'Atya'
        New-TestSbom (Join-Path $Path 'package.sbom.cdx.json') 'Atya.Foundation.Guards' '1.2.3' $primary
    }
    $monoBundle = Join-Path $temp 'mono-bundle'
    New-MonoBundle $monoBundle
    Test-Case 'monorepo bundle with the matching package-prefixed tag seals and verifies' {
        $sealed = New-SealedReleaseBundle $monoBundle 'AtyaLibraries/Atya' '1.2.3' 'refs/tags/Atya.Foundation.Guards/v1.2.3' $sourceCommit $monoPolicy
        Assert-Equal 'refs/tags/Atya.Foundation.Guards/v1.2.3' $sealed.SourceRef
        Assert-True (Test-SealedReleaseBundle $monoBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion) 'Monorepo sealed bundle verification failed.'
        # The re-check that runs before login and again before push refuses a swapped tag identity.
        Assert-Throws $prefixMismatch {
            Test-SealedReleaseBundle $monoBundle $sealed.PackageId $sealed.Version $sealed.Repository 'refs/tags/Atya.Foundation.Results/v1.2.3' $sealed.SourceCommit $sealed.PolicyVersion }
        Assert-Throws $prefixMismatch {
            Test-SealedReleaseBundle $monoBundle 'Atya.Foundation.Results' $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion }
    }
    foreach ($case in @(
            @{ Name = 'a different package id'; Ref = 'refs/tags/Atya.Foundation.Results/v1.2.3'; Message = $prefixMismatch },
            @{ Name = 'a prefix differing only in case'; Ref = 'refs/tags/Atya.Foundation.GuardS/v1.2.3'; Message = $prefixMismatch },
            @{ Name = 'an unprefixed tag in a multi-package repository'; Ref = 'refs/tags/v1.2.3'; Message = 'A repository that releases several packages requires a package-prefixed release tag.' },
            @{ Name = 'an empty prefix'; Ref = 'refs/tags//v1.2.3'; Message = $invalidRef },
            @{ Name = 'path traversal in the prefix'; Ref = 'refs/tags/../Atya.Foundation.Guards/v1.2.3'; Message = $invalidRef })) {
        Test-Case "monorepo seal rejects $($case.Name)" {
            $bundle = Join-Path $temp ('mono-reject-' + [Guid]::NewGuid().ToString('N'))
            New-MonoBundle $bundle
            Assert-Throws $case.Message { New-SealedReleaseBundle $bundle 'AtyaLibraries/Atya' '1.2.3' $case.Ref $sourceCommit $monoPolicy }
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $bundle 'release-manifest.json'))) 'A manifest was written for a rejected tag.'
        }
    }

    $missingSymbolBundle = Join-Path $temp 'missing-symbol-bundle'
    New-TestBundle $missingSymbolBundle
    Remove-Item -LiteralPath (Join-Path $missingSymbolBundle 'package.snupkg')
    Test-Case 'missing required symbol package fails' {
        Assert-Throws 'The release bundle must contain exactly one symbol package.' { New-SealedReleaseBundle $missingSymbolBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $duplicatePrimaryBundle = Join-Path $temp 'duplicate-primary-bundle'
    New-TestBundle $duplicatePrimaryBundle
    Copy-Item -LiteralPath (Join-Path $duplicatePrimaryBundle 'package.nupkg') -Destination (Join-Path $duplicatePrimaryBundle 'duplicate.nupkg')
    Test-Case 'duplicate primary package fails' {
        Assert-Throws 'The release bundle must contain exactly one primary package.' { New-SealedReleaseBundle $duplicatePrimaryBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $duplicateSymbolBundle = Join-Path $temp 'duplicate-symbol-bundle'
    New-TestBundle $duplicateSymbolBundle
    Copy-Item -LiteralPath (Join-Path $duplicateSymbolBundle 'package.snupkg') -Destination (Join-Path $duplicateSymbolBundle 'duplicate.snupkg')
    Test-Case 'duplicate symbol package fails' {
        Assert-Throws 'The release bundle must contain exactly one symbol package.' { New-SealedReleaseBundle $duplicateSymbolBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    foreach ($mismatch in @(
        @{ Name = 'PackageId'; PackageId = 'Atya.Foundation.Results'; Version = '1.2.3'; Repository = 'https://github.com/AtyaLibraries/Guards' },
        @{ Name = 'version'; PackageId = 'Atya.Foundation.Guards'; Version = '1.2.4'; Repository = 'https://github.com/AtyaLibraries/Guards' },
        @{ Name = 'repository provenance'; PackageId = 'Atya.Foundation.Guards'; Version = '1.2.3'; Repository = 'https://github.com/AtyaLibraries/Results' }
    )) {
        $bundle = Join-Path $temp ("mismatched-" + ($mismatch.Name -replace ' ', '-') + '-bundle')
        New-TestBundle $bundle
        Remove-Item -LiteralPath (Join-Path $bundle 'package.snupkg')
        New-TestPackage -Path (Join-Path $bundle 'package.snupkg') -SymbolsPackage -PackageId $mismatch.PackageId -Version $mismatch.Version -RepositoryUrl $mismatch.Repository
        Test-Case "mismatched $($mismatch.Name) across package pair fails" {
            Assert-Throws 'The primary and symbol package identities do not agree.' { New-SealedReleaseBundle $bundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
        }
    }

    $commitMismatchBundle = Join-Path $temp 'mismatched-commit-bundle'
    New-TestBundle $commitMismatchBundle
    Remove-Item -LiteralPath (Join-Path $commitMismatchBundle 'package.snupkg')
    New-TestPackage -Path (Join-Path $commitMismatchBundle 'package.snupkg') -SymbolsPackage -SourceCommit '1123456789012345678901234567890123456789'
    Test-Case 'mismatched source commit across package pair fails' {
        Assert-Throws 'The primary and symbol package identities do not agree.' { New-SealedReleaseBundle $commitMismatchBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $requestedCommitBundle = Join-Path $temp 'requested-commit-bundle'
    New-TestBundle $requestedCommitBundle
    Test-Case 'package and requested immutable commit mismatch fails' {
        Assert-Throws 'The package source commit does not match the requested release tag.' { New-SealedReleaseBundle $requestedCommitBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' '2123456789012345678901234567890123456789' $allowlistPath }
    }

    $requestedVersionBundle = Join-Path $temp 'requested-version-bundle'
    New-TestBundle $requestedVersionBundle
    Test-Case 'package and requested tag version mismatch fails' {
        Assert-Throws 'The requested tag and version do not agree.' { New-SealedReleaseBundle $requestedVersionBundle 'AtyaLibraries/Guards' '1.2.4' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $badSbomBundle = Join-Path $temp 'bad-sbom-bundle'
    New-TestBundle $badSbomBundle
    New-TestSbom (Join-Path $badSbomBundle 'package.sbom.cdx.json') 'Atya.Foundation.Results' '1.2.3' (Join-Path $badSbomBundle 'package.nupkg')
    Test-Case 'SBOM package identity mismatch fails' {
        Assert-Throws 'The package SBOM does not identify the validated primary package.' { New-SealedReleaseBundle $badSbomBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $badSbomVersionBundle = Join-Path $temp 'bad-sbom-version-bundle'
    New-TestBundle $badSbomVersionBundle
    $sbomPath = Join-Path $badSbomVersionBundle 'package.sbom.cdx.json'
    [IO.File]::WriteAllText($sbomPath, ([regex]::Replace([IO.File]::ReadAllText($sbomPath), '"specVersion"\s*:\s*"1\.6"', '"specVersion": "2.0"')), [Text.UTF8Encoding]::new($false))
    Test-Case 'unsupported SBOM version fails' {
        Assert-Throws 'The package SBOM uses an unsupported or ambiguous format version.' { New-SealedReleaseBundle $badSbomVersionBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $badSbomSchemaBundle = Join-Path $temp 'bad-sbom-schema-bundle'
    New-TestBundle $badSbomSchemaBundle
    $sbomPath = Join-Path $badSbomSchemaBundle 'package.sbom.cdx.json'
    [IO.File]::WriteAllText($sbomPath, ([IO.File]::ReadAllText($sbomPath).Replace('http://cyclonedx.org/schema/bom-1.6.schema.json', 'http://cyclonedx.org/schema/bom-1.5.schema.json')), [Text.UTF8Encoding]::new($false))
    Test-Case 'unsupported SBOM schema fails' {
        Assert-Throws 'The package SBOM uses an unsupported or ambiguous format version.' { New-SealedReleaseBundle $badSbomSchemaBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $malformedSbomBundle = Join-Path $temp 'malformed-sbom-bundle'
    New-TestBundle $malformedSbomBundle
    [IO.File]::WriteAllText((Join-Path $malformedSbomBundle 'package.sbom.cdx.json'), '{not-json', [Text.UTF8Encoding]::new($false))
    Test-Case 'malformed SBOM JSON fails with sanitized reason' {
        Assert-Throws 'The package SBOM is not valid JSON.' { New-SealedReleaseBundle $malformedSbomBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $missingSbomMetadataBundle = Join-Path $temp 'missing-sbom-metadata-bundle'
    New-TestBundle $missingSbomMetadataBundle
    [IO.File]::WriteAllText((Join-Path $missingSbomMetadataBundle 'package.sbom.cdx.json'), '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}', [Text.UTF8Encoding]::new($false))
    Test-Case 'missing SBOM identity metadata fails with sanitized reason' {
        Assert-Throws 'The package SBOM is missing required identity metadata.' { New-SealedReleaseBundle $missingSbomMetadataBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $unexpectedBundle = Join-Path $temp 'unexpected-bundle'
    New-TestBundle $unexpectedBundle
    [IO.File]::WriteAllText((Join-Path $unexpectedBundle 'unexpected.txt'), 'unexpected')
    Test-Case 'unexpected bundle file fails' {
        Assert-Throws 'The release bundle contains an unexpected artifact.' { New-SealedReleaseBundle $unexpectedBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    if ($env:OS -ne 'Windows_NT') {
        $caseBundle = Join-Path $temp 'case-bundle'
        New-TestBundle $caseBundle
        Move-Item -LiteralPath (Join-Path $caseBundle 'package.nupkg') -Destination (Join-Path $caseBundle 'package.NUPKG')
        Test-Case 'case-ambiguous bundle filename fails' {
            Assert-Throws 'The release bundle must contain exactly one primary package.' { New-SealedReleaseBundle $caseBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
        }
    }

    $unicodeBundle = Join-Path $temp 'unicode-bundle'
    New-TestBundle $unicodeBundle
    [IO.File]::WriteAllText((Join-Path $unicodeBundle "e$([char] 0x0301).txt"), 'unexpected')
    Test-Case 'Unicode-normalization bundle alias fails' {
        Assert-Throws 'The release bundle contains an unexpected artifact.' { New-SealedReleaseBundle $unicodeBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    if ($env:OS -ne 'Windows_NT') {
        $symlinkBundle = Join-Path $temp 'symlink-bundle'
        New-TestBundle $symlinkBundle
        Remove-Item -LiteralPath (Join-Path $symlinkBundle 'package.sbom.cdx.json')
        New-Item -ItemType SymbolicLink -Path (Join-Path $symlinkBundle 'package.sbom.cdx.json') -Target (Join-Path $symlinkBundle 'package.nupkg') | Out-Null
        Test-Case 'symlinked required bundle artifact fails' {
            Assert-Throws 'The release bundle contains an unsafe file type.' { New-SealedReleaseBundle $symlinkBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
        }
    }

    $unsafePathBundle = Join-Path $temp 'unsafe-path-bundle'
    New-TestBundle $unsafePathBundle
    New-Item -ItemType Directory -Path (Join-Path $unsafePathBundle 'nested') | Out-Null
    Test-Case 'nested bundle path fails' {
        Assert-Throws 'The release bundle contains an unsafe path or nested directory.' { New-SealedReleaseBundle $unsafePathBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $zeroLengthBundle = Join-Path $temp 'zero-length-bundle'
    New-TestBundle $zeroLengthBundle
    [IO.File]::WriteAllBytes((Join-Path $zeroLengthBundle 'package.sbom.cdx.json'), [byte[]] @())
    Test-Case 'zero-length required artifact fails' {
        Assert-Throws 'A required release artifact is empty or oversized.' { New-SealedReleaseBundle $zeroLengthBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $boundedBundle = Join-Path $temp 'bounded-bundle'
    New-TestBundle $boundedBundle
    Test-Case 'per-file bundle size boundary fails' {
        Assert-Throws 'A required release artifact is empty or oversized.' { New-SealedReleaseBundle $boundedBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath -MaximumSbomBytes 1 }
    }
    Test-Case 'aggregate bundle size boundary fails' {
        Assert-Throws 'The release bundle exceeds the aggregate size boundary.' { New-SealedReleaseBundle $boundedBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath -MaximumAggregateBytes 1 }
    }

    $unsafeArchiveBundle = Join-Path $temp 'unsafe-archive-bundle'
    New-TestBundle $unsafeArchiveBundle
    Remove-Item -LiteralPath (Join-Path $unsafeArchiveBundle 'package.nupkg')
    New-TestPackage -Path (Join-Path $unsafeArchiveBundle 'package.nupkg') -UnsafeArchivePath
    New-TestSbom (Join-Path $unsafeArchiveBundle 'package.sbom.cdx.json') 'Atya.Foundation.Guards' '1.2.3' (Join-Path $unsafeArchiveBundle 'package.nupkg')
    Test-Case 'unsafe package archive path fails' {
        Assert-Throws 'The package contains an unsafe or ambiguous archive entry.' { New-SealedReleaseBundle $unsafeArchiveBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    foreach ($archiveCase in @(
        @{ Name = 'duplicate archive path'; Switch = 'DuplicateArchivePath'; Expected = 'The package contains duplicate or case-ambiguous archive entries.' },
        @{ Name = 'case-ambiguous archive path'; Switch = 'CaseAmbiguousArchivePath'; Expected = 'The package contains duplicate or case-ambiguous archive entries.' },
        @{ Name = 'directory-file archive collision'; Switch = 'DirectoryFileArchiveCollision'; Expected = 'The package contains duplicate or case-ambiguous archive entries.' },
        @{ Name = 'non-normalized Unicode archive path'; Switch = 'NonCanonicalUnicodeArchivePath'; Expected = 'The package contains an unsafe or ambiguous archive entry.' }
    )) {
        $path = Join-Path $temp (($archiveCase.Name -replace ' ', '-') + '.nupkg')
        $arguments = @{ Path = $path }
        $arguments[$archiveCase.Switch] = $true
        New-TestPackage @arguments
        Test-Case "$($archiveCase.Name) fails" { Assert-Throws $archiveCase.Expected { Read-PackageIdentity $path } }
    }

    foreach ($pdbCase in @(
        @{ Name = 'malformed Portable PDB'; Malformed = $true; MissingSourceLink = $false },
        @{ Name = 'missing SourceLink'; Malformed = $false; MissingSourceLink = $true }
    )) {
        $bundle = Join-Path $temp (($pdbCase.Name -replace ' ', '-') + '-bundle')
        New-TestBundle $bundle
        Remove-Item -LiteralPath (Join-Path $bundle 'package.snupkg')
        New-TestPackage -Path (Join-Path $bundle 'package.snupkg') -SymbolsPackage -MalformedPortablePdb:$pdbCase.Malformed -MissingSourceLink:$pdbCase.MissingSourceLink
        Test-Case "$($pdbCase.Name) fails" {
            Assert-Throws 'The symbol package does not contain portable SourceLink-bound PDBs.' { New-SealedReleaseBundle $bundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
        }
    }

    $sourceLinkCommitBundle = Join-Path $temp 'source-link-commit-bundle'
    New-TestBundle $sourceLinkCommitBundle
    Remove-Item -LiteralPath (Join-Path $sourceLinkCommitBundle 'package.snupkg')
    New-TestPackage -Path (Join-Path $sourceLinkCommitBundle 'package.snupkg') -SymbolsPackage -SourceLinkCommit '3123456789012345678901234567890123456789'
    Test-Case 'SourceLink commit inconsistent with immutable release fails' {
        Assert-Throws 'The symbol package does not contain portable SourceLink-bound PDBs.' { New-SealedReleaseBundle $sourceLinkCommitBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $missingSymbolTypeBundle = Join-Path $temp 'missing-symbol-type-bundle'
    New-TestBundle $missingSymbolTypeBundle
    Remove-Item -LiteralPath (Join-Path $missingSymbolTypeBundle 'package.snupkg')
    New-TestPackage -Path (Join-Path $missingSymbolTypeBundle 'package.snupkg')
    Test-Case 'missing SymbolsPackage type fails' {
        Assert-Throws 'The symbol package does not declare exactly one SymbolsPackage type.' { New-SealedReleaseBundle $missingSymbolTypeBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath }
    }

    $hashTamperBundle = Join-Path $temp 'hash-tamper-bundle'
    New-TestBundle $hashTamperBundle
    $sealed = New-SealedReleaseBundle $hashTamperBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath
    $null = Test-SealedReleaseBundle $hashTamperBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion
    [IO.File]::AppendAllText((Join-Path $hashTamperBundle 'package.nupkg'), 'tamper')
    Test-Case 'artifact mutation between first and final pre-push verification fails' {
        Assert-Throws 'A sealed artifact hash or length does not match the release manifest.' { Test-SealedReleaseBundle $hashTamperBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion }
    }

    $manifestTamperBundle = Join-Path $temp 'manifest-tamper-bundle'
    New-TestBundle $manifestTamperBundle
    $sealed = New-SealedReleaseBundle $manifestTamperBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath
    $manifestPath = Join-Path $manifestTamperBundle 'release-manifest.json'
    [IO.File]::WriteAllText($manifestPath, ([IO.File]::ReadAllText($manifestPath).Replace('Atya.Foundation.Guards', 'Atya.Foundation.Results')), [Text.UTF8Encoding]::new($false))
    Test-Case 'release manifest identity tampering fails' {
        Assert-Throws 'The release manifest identity does not match the authorized release.' { Test-SealedReleaseBundle $manifestTamperBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion }
    }

    $manifestVersionBundle = Join-Path $temp 'manifest-version-bundle'
    New-TestBundle $manifestVersionBundle
    $sealed = New-SealedReleaseBundle $manifestVersionBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath
    $manifestPath = Join-Path $manifestVersionBundle 'release-manifest.json'
    [IO.File]::WriteAllText($manifestPath, ([IO.File]::ReadAllText($manifestPath).Replace('"schemaVersion": "1.0.0"', '"schemaVersion": "2.0.0"')), [Text.UTF8Encoding]::new($false))
    Test-Case 'unsupported release manifest schema fails' {
        Assert-Throws 'The release manifest uses an unsupported schema version.' { Test-SealedReleaseBundle $manifestVersionBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion }
    }

    $malformedManifestBundle = Join-Path $temp 'malformed-manifest-bundle'
    New-TestBundle $malformedManifestBundle
    $sealed = New-SealedReleaseBundle $malformedManifestBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath
    [IO.File]::WriteAllText((Join-Path $malformedManifestBundle 'release-manifest.json'), '{not-json', [Text.UTF8Encoding]::new($false))
    Test-Case 'malformed release manifest fails with sanitized reason' {
        Assert-Throws 'The release manifest is not valid JSON.' { Test-SealedReleaseBundle $malformedManifestBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion }
    }

    $manifestOmissionBundle = Join-Path $temp 'manifest-omission-bundle'
    New-TestBundle $manifestOmissionBundle
    $sealed = New-SealedReleaseBundle $manifestOmissionBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath
    $manifestPath = Join-Path $manifestOmissionBundle 'release-manifest.json'
    [IO.File]::WriteAllText($manifestPath, ([regex]::Replace([IO.File]::ReadAllText($manifestPath), '(?m)^  "sourceCommit":.*\n', '')), [Text.UTF8Encoding]::new($false))
    Test-Case 'release manifest identity omission fails' {
        Assert-Throws 'The release manifest is missing required metadata.' { Test-SealedReleaseBundle $manifestOmissionBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion }
    }

    $manifestDuplicateKeyBundle = Join-Path $temp 'manifest-duplicate-key-bundle'
    New-TestBundle $manifestDuplicateKeyBundle
    $sealed = New-SealedReleaseBundle $manifestDuplicateKeyBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath
    $manifestPath = Join-Path $manifestDuplicateKeyBundle 'release-manifest.json'
    $manifestText = [IO.File]::ReadAllText($manifestPath)
    $manifestText = $manifestText.Replace("  `"sourceCommit`": `"$sourceCommit`",`n", "  `"sourceCommit`": `"$sourceCommit`",`n  `"sourceCommit`": `"$sourceCommit`",`n")
    [IO.File]::WriteAllText($manifestPath, $manifestText, [Text.UTF8Encoding]::new($false))
    Test-Case 'release manifest duplicate key fails canonical verification' {
        Assert-Throws 'The release manifest is not in deterministic canonical form.' { Test-SealedReleaseBundle $manifestDuplicateKeyBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion }
    }

    $manifestReorderBundle = Join-Path $temp 'manifest-reorder-bundle'
    New-TestBundle $manifestReorderBundle
    $sealed = New-SealedReleaseBundle $manifestReorderBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath
    $manifestPath = Join-Path $manifestReorderBundle 'release-manifest.json'
    $manifestText = [IO.File]::ReadAllText($manifestPath)
    $repositoryLine = "  `"repository`": `"AtyaLibraries/Guards`",`n"
    $sourceRefLine = "  `"sourceRef`": `"refs/tags/v1.2.3`",`n"
    $manifestText = $manifestText.Replace($repositoryLine + $sourceRefLine, $sourceRefLine + $repositoryLine)
    [IO.File]::WriteAllText($manifestPath, $manifestText, [Text.UTF8Encoding]::new($false))
    Test-Case 'release manifest property reordering fails canonical verification' {
        Assert-Throws 'The release manifest is not in deterministic canonical form.' { Test-SealedReleaseBundle $manifestReorderBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion }
    }

    $manifestDuplicateSubjectBundle = Join-Path $temp 'manifest-duplicate-subject-bundle'
    New-TestBundle $manifestDuplicateSubjectBundle
    $sealed = New-SealedReleaseBundle $manifestDuplicateSubjectBundle 'AtyaLibraries/Guards' '1.2.3' 'v1.2.3' $sourceCommit $allowlistPath
    $manifestPath = Join-Path $manifestDuplicateSubjectBundle 'release-manifest.json'
    $manifestText = [IO.File]::ReadAllText($manifestPath).Replace('"name": "package.sbom.cdx.json"', '"name": "package.nupkg"')
    [IO.File]::WriteAllText($manifestPath, $manifestText, [Text.UTF8Encoding]::new($false))
    Test-Case 'release manifest duplicate subject name fails' {
        Assert-Throws 'A sealed artifact hash or length does not match the release manifest.' { Test-SealedReleaseBundle $manifestDuplicateSubjectBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion }
    }

    # ---- symbols = none (content-only packages: MSBuild SDK, dotnet templates) ----
    function New-ContentOnlyPackage {
        param(
            [Parameter(Mandatory)][string] $Path,
            [string] $PackageId = 'Atya.Build.Sdk',
            [string] $Version = '1.2.3',
            [string] $RepositoryUrl = 'https://github.com/AtyaLibraries/Atya.Build.Sdk',
            [string] $SourceCommit = '0123456789012345678901234567890123456789',
            [hashtable] $ExtraEntries = @{}
        )

        $archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
        try {
            $entries = [ordered]@{
                "$PackageId.nuspec" = [Text.Encoding]::UTF8.GetBytes("<?xml version=`"1.0`"?><package><metadata><id>$PackageId</id><version>$Version</version><packageTypes><packageType name=`"MSBuildSdk`" /></packageTypes><repository type=`"git`" url=`"$RepositoryUrl`" commit=`"$SourceCommit`" /></metadata></package>")
                'Sdk/Sdk.props' = [Text.Encoding]::UTF8.GetBytes('<Project />')
                'Sdk/Sdk.targets' = [Text.Encoding]::UTF8.GetBytes('<Project />')
                'Sdk/icon.png' = [byte[]] (0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0)
                'README.md' = [Text.Encoding]::UTF8.GetBytes('# Package')
            }
            foreach ($name in $ExtraEntries.Keys) { $entries[$name] = [byte[]] $ExtraEntries[$name] }
            foreach ($name in $entries.Keys) {
                $entry = $archive.CreateEntry($name)
                $stream = $entry.Open()
                try { $stream.Write($entries[$name], 0, $entries[$name].Length) }
                finally { $stream.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }

    function New-ContentOnlyBundle([string] $Path, [hashtable] $ExtraEntries = @{}, [switch] $WithSymbolPackage) {
        New-Item -ItemType Directory -Path $Path | Out-Null
        $primary = Join-Path $Path 'package.nupkg'
        New-ContentOnlyPackage -Path $primary -ExtraEntries $ExtraEntries
        New-TestSbom (Join-Path $Path 'package.sbom.cdx.json') 'Atya.Build.Sdk' '1.2.3' $primary
        if ($WithSymbolPackage) {
            New-TestPackage -Path (Join-Path $Path 'package.snupkg') -SymbolsPackage `
                -PackageId 'Atya.Build.Sdk' -RepositoryUrl 'https://github.com/AtyaLibraries/Atya.Build.Sdk'
        }
    }

    $contentOnlyBundle = Join-Path $temp 'content-only-bundle'
    New-ContentOnlyBundle $contentOnlyBundle
    $contentOnlyRepository = 'AtyaLibraries/Atya.Build.Sdk'
    Test-Case 'allowlist declares symbols none only for the three content-only packages' {
        $policy = Read-PublisherAllowlist $allowlistPath
        $none = @($policy.packages | Where-Object { $_.symbols -ceq 'none' } | ForEach-Object packageId | Sort-Object)
        Assert-Equal 'Atya.Build.Sdk|Atya.Templates.NuGetPackage|Atya.Templates.UiAutomation' ($none -join '|')
        foreach ($entry in $policy.packages) {
            Assert-True ($entry.symbols -cin @('required', 'none')) "Entry $($entry.packageId) has no explicit symbols policy."
        }
        Assert-Equal 'none' (Get-RepositorySymbolsPolicy $allowlistPath 'AtyaLibraries/Atya.Build.Sdk')
        Assert-Equal 'required' (Get-RepositorySymbolsPolicy $allowlistPath 'AtyaLibraries/Guards')
        Assert-Equal 'required' (Get-RepositorySymbolsPolicy $allowlistPath 'AtyaLibraries/Unlisted')
    }
    Test-Case 'deployed policy maps every moved package to the monorepo and declares symbols none for exactly three' {
        $deployed = Read-PublisherAllowlist $policyPath
        $none = @($deployed.packages | Where-Object { $_.symbols -ceq 'none' } | ForEach-Object packageId | Sort-Object)
        Assert-Equal 'Atya.Build.Sdk|Atya.Templates.NuGetPackage|Atya.Templates.UiAutomation' ($none -join '|')
        $monorepo = @($deployed.packages | Where-Object { $_.repository -ceq 'Atya' })
        Assert-Equal 29 $monorepo.Count
        foreach ($entry in $monorepo) { Assert-Equal 'main' $entry.defaultBranch }
        Assert-Equal 'mixed' (Get-RepositorySymbolsPolicy $policyPath 'AtyaLibraries/Atya')
        # Each template is a single-package, content-only repository of its own (ADR-14 amendment).
        foreach ($template in @('Atya.Templates.NuGetPackage', 'Atya.Templates.UiAutomation')) {
            $entry = @($deployed.packages | Where-Object { $_.packageId -ceq $template })
            Assert-Equal 1 $entry.Count
            Assert-Equal $template $entry[0].repository
            Assert-Equal 'none' (Get-RepositorySymbolsPolicy $policyPath "AtyaLibraries/$template")
        }
        Assert-Equal 'required' (Get-RepositorySymbolsPolicy $policyPath 'AtyaLibraries/Unlisted')
    }
    Test-Case 'content-only package released from the monorepo with a package-prefixed tag seals under the deployed policy' {
        $bundle = Join-Path $temp 'monorepo-content-only'
        New-Item -ItemType Directory -Path $bundle | Out-Null
        $primary = Join-Path $bundle 'package.nupkg'
        New-ContentOnlyPackage -Path $primary -RepositoryUrl 'https://github.com/AtyaLibraries/Atya'
        New-TestSbom (Join-Path $bundle 'package.sbom.cdx.json') 'Atya.Build.Sdk' '1.2.3' $primary
        $sealed = New-SealedReleaseBundle $bundle 'AtyaLibraries/Atya' '1.2.3' 'refs/tags/Atya.Build.Sdk/v1.2.3' $sourceCommit $policyPath
        Assert-Equal 'none' $sealed.Symbols
        Assert-Equal 'refs/tags/Atya.Build.Sdk/v1.2.3' $sealed.SourceRef
    }
    Test-Case 'managed package released from the monorepo without a symbol package fails closed under the deployed policy' {
        $bundle = Join-Path $temp 'monorepo-managed-no-symbols'
        New-Item -ItemType Directory -Path $bundle | Out-Null
        $primary = Join-Path $bundle 'package.nupkg'
        New-TestPackage -Path $primary -RepositoryUrl 'https://github.com/AtyaLibraries/Atya' -SourceLinkRepository 'Atya'
        New-TestSbom (Join-Path $bundle 'package.sbom.cdx.json') 'Atya.Foundation.Guards' '1.2.3' $primary
        Assert-Throws 'The release bundle must contain exactly one symbol package.' {
            New-SealedReleaseBundle $bundle 'AtyaLibraries/Atya' '1.2.3' 'refs/tags/Atya.Foundation.Guards/v1.2.3' $sourceCommit $policyPath }
    }
    Test-Case 'content-only package with a smuggled symbol package fails closed' {
        $bundle = Join-Path $temp 'content-only-with-symbols'
        New-ContentOnlyBundle $bundle -WithSymbolPackage
        Assert-Throws 'The symbols-none release bundle must not contain a symbol package.' {
            New-SealedReleaseBundle $bundle 'AtyaLibraries/Atya.Build.Sdk' '1.2.3' 'refs/tags/v1.2.3' $sourceCommit $allowlistPath }
    }
    Test-Case 'unknown symbols policy value in the allowlist fails closed' {
        $badPolicy = Join-Path $temp 'bad-symbols-policy.json'
        New-PolicyFile $badPolicy @([ordered]@{ packageId = 'Atya.Foundation.Guards'; repository = 'Guards'; defaultBranch = 'development'; symbols = 'optional' })
        Assert-Throws 'The publisher allowlist contains malformed metadata.' { Read-PublisherAllowlist $badPolicy }
    }
    Test-Case 'assembly-free symbols-none package seals without a symbol package and records the policy' {
        $sealed = New-SealedReleaseBundle $contentOnlyBundle $contentOnlyRepository '1.2.3' 'refs/tags/v1.2.3' $sourceCommit $allowlistPath
        Assert-Equal 'Atya.Build.Sdk' $sealed.PackageId
        Assert-Equal 'none' $sealed.Symbols
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $contentOnlyBundle 'package.snupkg'))) 'A symbol package appeared in a symbols-none bundle.'
        $manifestText = [IO.File]::ReadAllText((Join-Path $contentOnlyBundle 'release-manifest.json'))
        Assert-True ($manifestText.Contains('"symbols": "none"')) 'The manifest does not record symbols none.'
        Assert-True (-not $manifestText.Contains('package.snupkg')) 'The manifest references a symbol package.'
        Assert-True (Test-SealedReleaseBundle $contentOnlyBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion -ExpectedSymbols none) 'Symbols-none verification failed.'
        Assert-Throws 'The release bundle must contain exactly one symbol package.' {
            Test-SealedReleaseBundle $contentOnlyBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion
        }
    }
    Test-Case 'symbols-none manifest without the recorded policy fails verification' {
        $tamperedBundle = Join-Path $temp 'content-only-tampered'
        New-ContentOnlyBundle $tamperedBundle
        $sealed = New-SealedReleaseBundle $tamperedBundle $contentOnlyRepository '1.2.3' 'refs/tags/v1.2.3' $sourceCommit $allowlistPath
        $manifestPath = Join-Path $tamperedBundle 'release-manifest.json'
        [IO.File]::WriteAllText($manifestPath, ([IO.File]::ReadAllText($manifestPath).Replace("  `"symbols`": `"none`",`n", '')), [Text.UTF8Encoding]::new($false))
        Assert-Throws 'The release manifest does not record the symbols-none policy.' {
            Test-SealedReleaseBundle $tamperedBundle $sealed.PackageId $sealed.Version $sealed.Repository $sealed.SourceRef $sealed.SourceCommit $sealed.PolicyVersion -ExpectedSymbols none
        }
    }
    $binaryMessage = 'The symbols-none package contains a binary file.'
    foreach ($case in @(
        @{ Name = 'a .dll'; Entries = @{ 'tools/Atya.Build.Sdk.dll' = [byte[]] (1, 2, 3, 4) } },
        @{ Name = 'an .exe'; Entries = @{ 'tools/run.exe' = [byte[]] (1, 2, 3, 4) } },
        @{ Name = 'a native .so.1'; Entries = @{ 'runtimes/linux-x64/native/libx.so.1' = [byte[]] (1, 2, 3, 4) } },
        @{ Name = 'a .dylib'; Entries = @{ 'runtimes/osx-arm64/native/libx.dylib' = [byte[]] (1, 2, 3, 4) } },
        @{ Name = 'a PE image renamed to .txt'; Entries = @{ 'docs/notes.txt' = [byte[]] (0x4D, 0x5A, 0x90, 0x00, 0x03) } },
        @{ Name = 'an ELF image renamed to .dat'; Entries = @{ 'docs/blob.dat' = [byte[]] (0x7F, 0x45, 0x4C, 0x46, 0x02) } },
        @{ Name = 'a Mach-O image renamed to .md'; Entries = @{ 'docs/more.md' = [byte[]] (0xCF, 0xFA, 0xED, 0xFE, 0x07) } }
    )) {
        Test-Case "assembly-free package that carries $($case.Name) fails" {
            $binaryBundle = Join-Path $temp ('binary-bundle-' + [Guid]::NewGuid().ToString('N'))
            New-ContentOnlyBundle $binaryBundle $case.Entries
            Assert-Throws $binaryMessage { New-SealedReleaseBundle $binaryBundle $contentOnlyRepository '1.2.3' 'refs/tags/v1.2.3' $sourceCommit $allowlistPath }
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $binaryBundle 'release-manifest.json'))) 'A manifest was written for a rejected package.'
        }
    }
    $archiveMessage = 'The symbols-none package contains a nested archive.'
    foreach ($case in @(
        @{ Name = 'a nested .zip'; Entries = @{ 'tools/payload.zip' = [byte[]] (0x50, 0x4B, 0x03, 0x04, 0, 0) } },
        @{ Name = 'a nested .zip with no content'; Entries = @{ 'tools/empty.zip' = [byte[]] (1) } },
        @{ Name = 'a nested .nupkg'; Entries = @{ 'tools/inner.nupkg' = [byte[]] (1, 2) } },
        @{ Name = 'a nested .snupkg'; Entries = @{ 'tools/inner.snupkg' = [byte[]] (1, 2) } },
        @{ Name = 'a .tgz'; Entries = @{ 'tools/a.tgz' = [byte[]] (1, 2) } },
        @{ Name = 'a .tar'; Entries = @{ 'tools/a.tar' = [byte[]] (1, 2) } },
        @{ Name = 'a .gz'; Entries = @{ 'tools/a.gz' = [byte[]] (1, 2) } },
        @{ Name = 'a .7z'; Entries = @{ 'tools/a.7z' = [byte[]] (1, 2) } },
        @{ Name = 'a .rar'; Entries = @{ 'tools/a.rar' = [byte[]] (1, 2) } },
        @{ Name = 'a zip renamed to .dat'; Entries = @{ 'docs/blob.dat' = [byte[]] (0x50, 0x4B, 0x03, 0x04, 0x14, 0) } }
    )) {
        Test-Case "assembly-free package that carries $($case.Name) fails" {
            $archiveBundle = Join-Path $temp ('archive-bundle-' + [Guid]::NewGuid().ToString('N'))
            New-ContentOnlyBundle $archiveBundle $case.Entries
            Assert-Throws $archiveMessage { New-SealedReleaseBundle $archiveBundle $contentOnlyRepository '1.2.3' 'refs/tags/v1.2.3' $sourceCommit $allowlistPath }
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $archiveBundle 'release-manifest.json'))) 'A manifest was written for a rejected package.'
        }
    }
    Test-Case 'symbols-none package that ships a .snupkg fails' {
        $withSymbols = Join-Path $temp 'content-only-with-snupkg'
        New-ContentOnlyBundle $withSymbols -WithSymbolPackage
        Assert-Throws 'The symbols-none release bundle must not contain a symbol package.' {
            New-SealedReleaseBundle $withSymbols $contentOnlyRepository '1.2.3' 'refs/tags/v1.2.3' $sourceCommit $allowlistPath
        }
    }
    Test-Case 'managed package cannot use the symbols-none path' {
        $managedAsNone = Join-Path $temp 'managed-without-symbols'
        New-Item -ItemType Directory -Path $managedAsNone | Out-Null
        $primary = Join-Path $managedAsNone 'package.nupkg'
        New-TestPackage -Path $primary
        New-TestSbom (Join-Path $managedAsNone 'package.sbom.cdx.json') 'Atya.Foundation.Guards' '1.2.3' $primary
        Assert-Throws 'The release bundle must contain exactly one symbol package.' {
            New-SealedReleaseBundle $managedAsNone 'AtyaLibraries/Guards' '1.2.3' 'refs/tags/v1.2.3' $sourceCommit $allowlistPath
        }
    }
    Test-Case 'symbols-none package is still bound to its allowlisted repository' {
        $wrongRepoBundle = Join-Path $temp 'content-only-wrong-repo'
        New-ContentOnlyBundle $wrongRepoBundle
        Assert-Throws 'Package repository provenance does not match the requested repository.' {
            New-SealedReleaseBundle $wrongRepoBundle 'AtyaLibraries/Guards' '1.2.3' 'refs/tags/v1.2.3' $sourceCommit $allowlistPath
        }
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
    Test-Case 'complete sealed bundle is retained and attested before credentials and push' {
        $authorize = $publishJob.IndexOf('Validate, complete, and seal release bundle', [StringComparison]::Ordinal)
        $retain = $publishJob.IndexOf('Retain complete sealed release bundle', [StringComparison]::Ordinal)
        $attest = $publishJob.IndexOf('Attest complete sealed release bundle', [StringComparison]::Ordinal)
        $verify = $publishJob.IndexOf('Verify attested bytes before credential acquisition', [StringComparison]::Ordinal)
        $login = $publishJob.IndexOf('Log in to NuGet.org', [StringComparison]::Ordinal)
        $push = $publishJob.IndexOf('Push package', [StringComparison]::Ordinal)
        Assert-True ($authorize -ge 0 -and $authorize -lt $retain -and $retain -lt $attest -and $attest -lt $verify -and $verify -lt $login -and $login -lt $push) 'The release bundle is not sealed, retained, attested, and verified before credential acquisition.'
        $gatedSteps = $publishJob.Substring($retain, $login - $retain)
        Assert-True ($gatedSteps -notmatch 'continue-on-error:\s*true') 'A retention, attestation, or verification failure can be ignored before login.'
    }
    Test-Case 'push step re-verifies the sealed bundle immediately before publication' {
        $pushStep = $publishJob.Substring($publishJob.IndexOf('Push package', [StringComparison]::Ordinal))
        $verify = $pushStep.IndexOf('Verify-SealedReleaseBundle.ps1', [StringComparison]::Ordinal)
        $publish = $pushStep.IndexOf('dotnet nuget push ./inbound/package.nupkg', [StringComparison]::Ordinal)
        Assert-True ($verify -ge 0 -and $verify -lt $publish) 'The attested release bundle is not re-verified immediately before publication.'
        Assert-True ($pushStep.Substring($verify, $publish - $verify) -notmatch 'Copy-Item|Move-Item|Rename-Item|Set-Content|Add-Content|WriteAll|dotnet\s+(?:build|pack)') 'A mutation can occur between final verification and publication.'
    }
    Test-Case 'immutable source commit is bound through package metadata, SourceLink, manifest, and verification' {
        Assert-True ($buildJob -match 'commit:\s*\$\{\{\s*steps\.release_commit\.outputs\.commit\s*\}\}') 'The verified tag commit is not a trusted build output.'
        Assert-True ($publishJob -match 'REQUESTED_COMMIT:\s*\$\{\{\s*needs\.build\.outputs\.commit\s*\}\}') 'The privileged gate does not receive the verified source commit.'
        Assert-True ($publishJob -match '-RequestedCommit\s+\$env:REQUESTED_COMMIT' -and $publishJob -match "-ExpectedCommit '\$\{\{ steps\.release\.outputs\.commit \}\}'") 'The source commit is not sealed and reverified.'
    }
    Test-Case 'publication uses an exact pinned .NET and NuGet CLI' {
        Assert-True ($publishJob -match 'name:\s*Setup pinned publication CLI' -and $publishJob -match 'dotnet-version:\s*10\.0\.301') 'The privileged NuGet CLI is not pinned to the accepted SDK.'
    }
    Test-Case 'attestation uses four exact explicit subjects in one pinned action invocation' {
        $attestStart = $publishJob.IndexOf('Attest complete sealed release bundle', [StringComparison]::Ordinal)
        $verifyStart = $publishJob.IndexOf('Verify attested bytes before credential acquisition', [StringComparison]::Ordinal)
        $attestStep = $publishJob.Substring($attestStart, $verifyStart - $attestStart)
        $expectedSubjects = @('./inbound/package.nupkg', './inbound/package.snupkg', './inbound/package.sbom.cdx.json', './inbound/release-manifest.json')
        $actualSubjects = @([regex]::Matches($attestStep, '(?m)^\s+(\./inbound/[^\s]+)\s*$') | ForEach-Object { $_.Groups[1].Value })
        Assert-Equal ($expectedSubjects -join "`n") ($actualSubjects -join "`n")
        Assert-True ($attestStep -notmatch '[*?\[]') 'Attestation subjects use wildcard expansion.'
        Assert-True ($attestStep -match 'actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be') 'The reviewed attestation action commit is not pinned.'
    }
    Test-Case 'workflow actions use immutable SHA references' {
        $uses = [regex]::Matches($workflow, '(?m)^\s*uses:\s*[^\s]+@([^\s]+)')
        Assert-True ($uses.Count -gt 0) 'No workflow actions were found.'
        foreach ($use in $uses) {
            Assert-True ($use.Groups[1].Value -cmatch '^[0-9a-f]{40}$') "Mutable action reference found: $($use.Value)"
        }
    }
    Test-Case 'workflow carries one bounded and complete release bundle' {
        Assert-True ($workflow -match 'release-bundle/package\.nupkg' -and $workflow -match 'release-bundle/package\.snupkg' -and $workflow -match 'release-bundle/package\.sbom\.cdx\.json') 'The inbound artifact does not contain the exact required release files.'
        Assert-True ($workflow -match '\$packages\.Count -ne 1') 'Ambiguous package output check is missing.'
        Assert-True ($workflow -match '\$symbolPackages\.Count -ne 1' -and $workflow -match '\$sboms\.Count -ne 1') 'Complete bundle cardinality checks are missing.'
        Assert-True ($workflow -match '268435456' -and $workflow -match '8388608' -and $workflow -match '545259520') 'Release bundle size boundaries are missing.'
        Assert-True ($workflow -match 'retention-days:\s*1' -and $workflow -match 'retention-days:\s*90') 'Inbound or sealed artifact retention is not bounded.'
        Assert-True ($publishJob -match 'inbound/release-manifest\.json') 'The deterministic release manifest is not retained and attested.'
        Assert-True ($publishJob -notmatch '(?s)Validate, complete, and seal release bundle.*(?:Copy-Item|Move-Item|Rename-Item|dotnet\s+(?:build|pack)).*Log in to NuGet\.org') 'Artifact bytes can be rebuilt, copied, or renamed after sealing.'
    }
    Test-Case 'content-only attestation uses three exact subjects and is gated on the symbols policy' {
        $contentStart = $publishJob.IndexOf('Attest content-only sealed release bundle', [StringComparison]::Ordinal)
        $completeStart = $publishJob.IndexOf('Attest complete sealed release bundle', [StringComparison]::Ordinal)
        $verifyStart = $publishJob.IndexOf('Verify attested bytes before credential acquisition', [StringComparison]::Ordinal)
        Assert-True ($contentStart -ge 0 -and $contentStart -lt $completeStart -and $completeStart -lt $verifyStart) 'Attestation steps are missing or out of order.'
        $contentStep = $publishJob.Substring($contentStart, $completeStart - $contentStart)
        $completeStep = $publishJob.Substring($completeStart, $verifyStart - $completeStart)
        $subjects = @([regex]::Matches($contentStep, '(?m)^\s+(\./inbound/[^\s]+)\s*$') | ForEach-Object { $_.Groups[1].Value })
        Assert-Equal ('./inbound/package.nupkg', './inbound/package.sbom.cdx.json', './inbound/release-manifest.json' -join "`n") ($subjects -join "`n")
        Assert-True ($contentStep.Contains("if: steps.release.outputs.symbols == 'none'") -and $completeStep.Contains("if: steps.release.outputs.symbols != 'none'")) 'Attestation steps are not mutually exclusive on the sealed symbols policy.'
        Assert-True ($contentStep -match 'actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be' -and $contentStep -notmatch 'continue-on-error') 'The content-only attestation is not pinned or can be ignored.'
    }
    Test-Case 'sealed symbols policy is output by the trusted gate and re-verified before login and push' {
        Assert-True ((Get-Content -LiteralPath (Join-Path $root 'scripts/Seal-ReleaseBundle.ps1') -Raw).Contains('symbols=')) 'The trusted gate does not output the symbols policy.'
        $beforeLogin = $publishJob.Substring(0, $publishJob.IndexOf('Log in to NuGet.org', [StringComparison]::Ordinal))
        Assert-True ($beforeLogin.Contains("-ExpectedSymbols '`${{ steps.release.outputs.symbols }}'")) 'The pre-credential verification does not bind the symbols policy.'
        $pushStep = $publishJob.Substring($publishJob.IndexOf('Push package', [StringComparison]::Ordinal))
        Assert-True ($pushStep.Contains("-ExpectedSymbols '`${{ steps.release.outputs.symbols }}'")) 'The push-time verification does not bind the symbols policy.'
    }
    Test-Case 'build job shapes the bundle from the trusted allowlist but cannot choose the policy' {
        Assert-True ($buildJob.Contains('Get-RepositorySymbolsPolicy') -and $buildJob.Contains('./trusted-publisher/policy/publisher-allowlist.json')) 'The staging step does not read the trusted allowlist.'
        Assert-True ($buildJob -notmatch 'github\.event\.inputs\.symbols|inputs\.symbols') 'A dispatch input can influence the symbols policy.'
        Assert-True ($publishJob -notmatch 'inputs\.symbols') 'A dispatch input can influence the trusted symbols policy.'
    }
}
finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}

Write-Host "Publisher security tests: $script:Passed passed; $script:Failed failed."
if ($script:Failed -ne 0) { exit 1 }
