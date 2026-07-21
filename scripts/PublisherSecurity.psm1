Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-SupportedSemanticVersion {
    param([Parameter(Mandatory)][string] $Version)

    $numericIdentifier = '(?:0|[1-9][0-9]*)'
    $preReleaseIdentifier = '(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
    return $Version -cmatch "^$numericIdentifier\.$numericIdentifier\.$numericIdentifier(?:-$preReleaseIdentifier(?:\.$preReleaseIdentifier)*)?$"
}

function ConvertTo-CanonicalRepository {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Repository)

    if ($Repository.Length -gt 128 -or $Repository.EndsWith('.git', [StringComparison]::OrdinalIgnoreCase) -or
        $Repository -cnotmatch '^AtyaLibraries/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$') {
        throw 'The source repository identity is not an approved AtyaLibraries owner/name value.'
    }

    return $Repository
}

function ConvertTo-CanonicalReleaseRef {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Ref)

    if ($Ref.Length -gt 128) {
        throw 'The source ref is too long.'
    }

    $version = if ($Ref -cmatch '^refs/tags/v(.+)$') {
        $Matches[1]
    }
    elseif ($Ref -cmatch '^v(.+)$') {
        $Matches[1]
    }
    else {
        throw 'The source ref is not an immutable release tag.'
    }

    if (-not (Test-SupportedSemanticVersion $version)) {
        throw 'The release tag does not contain a supported semantic version.'
    }

    return [pscustomobject]@{
        Ref = "refs/tags/v$version"
        Version = $version
    }
}

function ConvertTo-SafeRelativePath {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string] $Path,
        [Parameter(Mandatory)][string] $Name,
        [switch] $AllowEmpty
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($AllowEmpty) { return '' }
        throw "$Name is required."
    }

    if ($Path.Length -gt 240 -or $Path.Contains('\') -or $Path.StartsWith('/') -or
        $Path.EndsWith('/') -or $Path.Contains('//') -or
        $Path -cnotmatch '^[A-Za-z0-9._/-]+$') {
        throw "$Name is not a safe repository-relative path."
    }

    $segments = @($Path.Split('/', [StringSplitOptions]::RemoveEmptyEntries))
    if ($segments.Count -eq 0 -or $segments -contains '..' -or $segments -contains '.') {
        throw "$Name is not a safe repository-relative path."
    }

    return ($segments -join '/')
}

function ConvertFrom-PackageRepositoryUrl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Url)

    if ($Url.Length -gt 512) {
        throw 'Package repository metadata is too long.'
    }

    if ($Url -cnotmatch '^https://github\.com/AtyaLibraries/[A-Za-z0-9][A-Za-z0-9._-]{0,99}(?:\.git)?/?$') {
        throw 'Package repository metadata is not a supported canonical GitHub URL.'
    }

    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref] $uri) -or
        $uri.Scheme -cne 'https' -or $uri.Host -cne 'github.com' -or
        -not $uri.IsDefaultPort -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        throw 'Package repository metadata is not a supported canonical GitHub URL.'
    }

    $path = $uri.AbsolutePath.TrimEnd('/')
    if ($path.EndsWith('.git', [StringComparison]::Ordinal)) {
        $path = $path.Substring(0, $path.Length - 4)
    }

    if ($path -cnotmatch '^/AtyaLibraries/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$') {
        throw 'Package repository metadata does not identify an approved AtyaLibraries repository.'
    }

    return $path.TrimStart('/')
}

function Read-PackageIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $PackagePath,
        [long] $MaximumPackageBytes = 268435456,
        [int] $MaximumEntries = 4096,
        [long] $MaximumNuspecBytes = 1048576,
        [long] $MaximumExpandedBytes = 536870912,
        [ValidateSet('.nupkg', '.snupkg')][string] $ExpectedExtension = '.nupkg',
        [switch] $RequireSymbolsPackage
    )

    try {
        $file = Get-Item -LiteralPath $PackagePath -ErrorAction Stop
    }
    catch {
        throw 'The package artifact is missing, empty, oversized, or has an invalid extension.'
    }
    if (-not $file.PSIsContainer -and $file.Extension -ceq $ExpectedExtension -and
        $file.Length -gt 0 -and $file.Length -le $MaximumPackageBytes) {
        # Continue.
    }
    else {
        throw 'The package artifact is missing, empty, oversized, or has an invalid extension.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try {
        $archive = [IO.Compression.ZipFile]::OpenRead($file.FullName)
    }
    catch {
        throw 'The package artifact is not a valid ZIP archive.'
    }
    try {
        if ($archive.Entries.Count -gt $MaximumEntries) {
            throw 'The package contains too many entries.'
        }

        [long] $expandedBytes = 0
        $entryPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $archive.Entries) {
            $entryPath = $entry.FullName
            $normalizedEntryPath = $entryPath.TrimEnd('/')
            $segments = @($normalizedEntryPath.Split('/'))
            $unixMode = (($entry.ExternalAttributes -shr 16) -band 0xF000)
            if ([string]::IsNullOrEmpty($normalizedEntryPath) -or $entryPath.Contains('\') -or
                $entryPath.StartsWith('/') -or $entryPath.Contains(':') -or $entryPath.EndsWith('//') -or
                -not [string]::Equals($entryPath, $entryPath.Normalize([Text.NormalizationForm]::FormC), [StringComparison]::Ordinal) -or
                $segments.Count -eq 0 -or $segments -contains '' -or $segments -contains '.' -or $segments -contains '..' -or
                $unixMode -eq 0xA000) {
                throw 'The package contains an unsafe or ambiguous archive entry.'
            }
            if (-not $entryPaths.Add($normalizedEntryPath)) {
                throw 'The package contains duplicate or case-ambiguous archive entries.'
            }
            if ($entry.Length -lt 0 -or $expandedBytes -gt ($MaximumExpandedBytes - $entry.Length)) {
                throw 'The package expanded content exceeds the validation boundary.'
            }
            $expandedBytes += $entry.Length
        }

        $nuspecs = @($archive.Entries | Where-Object {
            -not [string]::IsNullOrEmpty($_.Name) -and
            $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase)
        })
        if ($nuspecs.Count -ne 1) {
            throw 'The package must contain exactly one nuspec.'
        }

        $nuspec = $nuspecs[0]
        if ($nuspec.Length -le 0 -or $nuspec.Length -gt $MaximumNuspecBytes) {
            throw 'The package nuspec is empty or oversized.'
        }

        $stream = $nuspec.Open()
        try {
            $settings = [Xml.XmlReaderSettings]::new()
            $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver = $null
            $settings.MaxCharactersInDocument = $MaximumNuspecBytes
            $reader = $null
            try {
                $reader = [Xml.XmlReader]::Create($stream, $settings)
                try {
                    $document = [Xml.XmlDocument]::new()
                    $document.XmlResolver = $null
                    $document.Load($reader)
                }
                finally {
                    if ($null -ne $reader) { $reader.Dispose() }
                }
            }
            catch {
                throw 'The package nuspec is not valid safe XML.'
            }
        }
        finally {
            $stream.Dispose()
        }

        if ($null -eq $document.DocumentElement -or $document.DocumentElement.LocalName -cne 'package') {
            throw 'The package nuspec does not contain a package root element.'
        }

        $manager = [Xml.XmlNamespaceManager]::new($document.NameTable)
        $namespace = $document.DocumentElement.NamespaceURI
        if ($namespace) {
            $manager.AddNamespace('n', $namespace)
            $metadataNodes = @($document.SelectNodes('/n:package/n:metadata', $manager))
        }
        else {
            $metadataNodes = @($document.SelectNodes('/package/metadata'))
        }

        if ($metadataNodes.Count -ne 1) { throw 'The package nuspec must contain exactly one metadata element.' }
        $metadata = $metadataNodes[0]
        $idNodes = @($metadata.ChildNodes | Where-Object {
            $_ -is [Xml.XmlElement] -and $_.LocalName -ceq 'id' -and $_.NamespaceURI -ceq $namespace
        })
        $versionNodes = @($metadata.ChildNodes | Where-Object {
            $_ -is [Xml.XmlElement] -and $_.LocalName -ceq 'version' -and $_.NamespaceURI -ceq $namespace
        })
        $repositoryNodes = @($metadata.ChildNodes | Where-Object {
            $_ -is [Xml.XmlElement] -and $_.LocalName -ceq 'repository' -and $_.NamespaceURI -ceq $namespace
        })
        if ($idNodes.Count -ne 1 -or $versionNodes.Count -ne 1 -or $repositoryNodes.Count -ne 1) {
            throw 'The package nuspec must contain exactly one id, version, and repository element.'
        }

        $packageId = $idNodes[0].InnerText
        if ($packageId -cnotmatch '^Atya\.[A-Z][A-Za-z0-9]*(?:\.[A-Z][A-Za-z0-9]*)+$' -or $packageId.Length -gt 128) {
            throw 'The package id is missing or malformed.'
        }

        $packageVersion = $versionNodes[0].InnerText
        if ($packageVersion.Length -gt 128 -or -not (Test-SupportedSemanticVersion $packageVersion)) {
            throw 'The package version is missing or malformed.'
        }

        $repositoryUrl = $repositoryNodes[0].GetAttribute('url')
        if ([string]::IsNullOrWhiteSpace($repositoryUrl)) {
            throw 'The package repository URL is missing.'
        }
        $repositoryCommit = $repositoryNodes[0].GetAttribute('commit')
        if ($repositoryCommit -cnotmatch '^[0-9a-f]{40}$') {
            throw 'The package repository commit is missing or malformed.'
        }

        if ($RequireSymbolsPackage) {
            $packageTypes = @($metadata.ChildNodes | Where-Object {
                $_ -is [Xml.XmlElement] -and $_.LocalName -ceq 'packageTypes' -and $_.NamespaceURI -ceq $namespace
            })
            $symbolTypes = @(if ($packageTypes.Count -eq 1) {
                $packageTypes[0].ChildNodes | Where-Object {
                    $_ -is [Xml.XmlElement] -and $_.LocalName -ceq 'packageType' -and
                    $_.NamespaceURI -ceq $namespace -and $_.GetAttribute('name') -ceq 'SymbolsPackage'
                }
            }
            else { @() })
            if ($packageTypes.Count -ne 1 -or $symbolTypes.Count -ne 1) {
                throw 'The symbol package does not declare exactly one SymbolsPackage type.'
            }
        }

        return [pscustomobject]@{
            PackageId = $packageId
            Version = $packageVersion
            Repository = ConvertFrom-PackageRepositoryUrl -Url $repositoryUrl
            SourceCommit = $repositoryCommit
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Read-PublisherAllowlist {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $AllowlistPath)

    $file = Get-Item -LiteralPath $AllowlistPath -ErrorAction Stop
    if ($file.Length -le 0 -or $file.Length -gt 1048576) {
        throw 'The publisher allowlist is empty or oversized.'
    }

    try {
        $policy = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    }
    catch {
        throw 'The publisher allowlist is not valid JSON.'
    }

    if ($policy.schemaVersion -cne '1.0.0' -or
        $policy.policyVersion -cnotmatch '^1\.[0-9]+\.[0-9]+$' -or
        $null -eq $policy.packages) {
        throw 'The publisher allowlist uses an unsupported policy schema or version.'
    }

    $entries = @($policy.packages)
    if ($entries.Count -eq 0 -or $entries.Count -gt 512) {
        throw 'The publisher allowlist contains an invalid number of entries.'
    }

    $seenIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $seenPairs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        $id = [string] $entry.packageId
        $repository = [string] $entry.repository
        $defaultBranch = [string] $entry.defaultBranch
        if ($id -cnotmatch '^Atya\.[A-Z][A-Za-z0-9]*(?:\.[A-Z][A-Za-z0-9]*)+$' -or
            $repository -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' -or
            $defaultBranch -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$') {
            throw 'The publisher allowlist contains malformed metadata.'
        }
        if (-not $seenIds.Add($id) -or -not $seenPairs.Add("$id`n$repository")) {
            throw 'The publisher allowlist contains duplicate or ambiguous package metadata.'
        }
    }

    return $policy
}

function Test-PackageAuthorization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Identity,
        [Parameter(Mandatory)][string] $RequestedRepository,
        [Parameter(Mandatory)] $Policy
    )

    $canonicalRequest = ConvertTo-CanonicalRepository -Repository $RequestedRepository
    $requestedSlug = $canonicalRequest.Substring('AtyaLibraries/'.Length)
    if ($Identity.Repository -cne $canonicalRequest) {
        throw 'Package repository provenance does not match the requested repository.'
    }

    $matches = @($Policy.packages | Where-Object { [string] $_.packageId -ceq $Identity.PackageId })
    if ($matches.Count -ne 1) {
        throw 'The derived package id is not uniquely authorized by publisher policy.'
    }
    if ([string] $matches[0].repository -cne $requestedSlug) {
        throw 'The derived package id is not authorized for the requested repository.'
    }

    return [pscustomobject]@{
        PackageId = $Identity.PackageId
        Repository = $canonicalRequest
        PolicyVersion = [string] $Policy.policyVersion
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ReleaseBundleLayout {
    param(
        [Parameter(Mandatory)][string] $BundlePath,
        [switch] $IncludeManifest,
        [long] $MaximumPackageBytes = 268435456,
        [long] $MaximumSbomBytes = 8388608,
        [long] $MaximumManifestBytes = 65536,
        [long] $MaximumAggregateBytes = 545325056
    )

    try { $root = Get-Item -LiteralPath $BundlePath -ErrorAction Stop }
    catch { throw 'The release bundle is missing or unreadable.' }
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The release bundle root is not a safe directory.'
    }

    $entries = @(Get-ChildItem -LiteralPath $root.FullName -Force -Recurse)
    if (@($entries | Where-Object PSIsContainer).Count -ne 0) {
        throw 'The release bundle contains an unsafe path or nested directory.'
    }
    $files = @($entries | Where-Object { -not $_.PSIsContainer })
    $primaryFiles = @($files | Where-Object Extension -CEQ '.nupkg')
    $symbolFiles = @($files | Where-Object Extension -CEQ '.snupkg')
    if ($primaryFiles.Count -ne 1) { throw 'The release bundle must contain exactly one primary package.' }
    if ($symbolFiles.Count -ne 1) { throw 'The release bundle must contain exactly one symbol package.' }

    $expectedNames = @('package.nupkg', 'package.snupkg', 'package.sbom.cdx.json')
    if ($IncludeManifest) { $expectedNames += 'release-manifest.json' }
    if ($files.Count -ne $expectedNames.Count) {
        throw 'The release bundle contains an unexpected artifact.'
    }

    $result = @{}
    [long] $aggregateBytes = 0
    foreach ($name in $expectedNames) {
        $matches = @($files | Where-Object { $_.Name -ceq $name -and $_.DirectoryName -ceq $root.FullName })
        if ($matches.Count -ne 1) { throw 'The release bundle is missing a required canonical artifact.' }
        $file = $matches[0]
        if (($file.Attributes -band ([IO.FileAttributes]::ReparsePoint -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System)) -ne 0) {
            throw 'The release bundle contains an unsafe file type.'
        }
        if ($env:OS -eq 'Windows_NT') {
            $streams = @(Get-Item -LiteralPath $file.FullName -Stream * -ErrorAction Stop)
            if ($streams.Count -ne 1 -or $streams[0].Stream -notin @(':$DATA', '$DATA')) {
                throw 'The release bundle contains an alternate data stream.'
            }
        }

        $maximum = if ($name -in @('package.nupkg', 'package.snupkg')) { $MaximumPackageBytes }
            elseif ($name -ceq 'package.sbom.cdx.json') { $MaximumSbomBytes }
            else { $MaximumManifestBytes }
        if ($file.Length -le 0 -or $file.Length -gt $maximum) {
            throw 'A required release artifact is empty or oversized.'
        }
        if ($aggregateBytes -gt ($MaximumAggregateBytes - $file.Length)) {
            throw 'The release bundle exceeds the aggregate size boundary.'
        }
        $aggregateBytes += $file.Length
        $result[$name] = $file
    }

    return $result
}

function Test-PortablePdbSourceLinkBytes {
    param(
        [Parameter(Mandatory)][byte[]] $Bytes,
        [Parameter(Mandatory)][string] $ExpectedSourceUrlPrefix
    )

    try {
        # Validate the ECMA-335 metadata root and bounded stream directory. A
        # signature plus an unrelated URL in a blob heap is not a Portable PDB.
        if ($Bytes.Length -lt 32 -or [BitConverter]::ToUInt32($Bytes, 0) -ne 0x424A5342) { return $false }
        $versionLength = [BitConverter]::ToUInt32($Bytes, 12)
        if ($versionLength -eq 0 -or $versionLength -gt 256 -or 16 + $versionLength + 4 -gt $Bytes.Length) { return $false }
        $streamDirectory = (16 + [int] $versionLength + 3) -band -4
        if ($streamDirectory + 4 -gt $Bytes.Length) { return $false }
        $streamCount = [BitConverter]::ToUInt16($Bytes, $streamDirectory + 2)
        if ($streamCount -lt 5 -or $streamCount -gt 16) { return $false }

        $cursor = $streamDirectory + 4
        $streams = @{}
        for ($index = 0; $index -lt $streamCount; $index++) {
            if ($cursor + 8 -gt $Bytes.Length) { return $false }
            $offset = [BitConverter]::ToUInt32($Bytes, $cursor)
            $size = [BitConverter]::ToUInt32($Bytes, $cursor + 4)
            $nameStart = $cursor + 8
            $nameEnd = $nameStart
            while ($nameEnd -lt $Bytes.Length -and $nameEnd -lt $nameStart + 32 -and $Bytes[$nameEnd] -ne 0) { $nameEnd++ }
            if ($nameEnd -ge $Bytes.Length -or $nameEnd -ge $nameStart + 32) { return $false }
            $name = [Text.Encoding]::ASCII.GetString($Bytes, $nameStart, $nameEnd - $nameStart)
            if ($name -cnotmatch '^#[A-Za-z~]+$' -or $streams.ContainsKey($name)) { return $false }
            $cursor = ($nameEnd + 1 + 3) -band -4
            if ($size -eq 0 -or $offset -gt $Bytes.Length -or $size -gt ($Bytes.Length - $offset)) { return $false }
            $streams[$name] = [pscustomobject]@{ Offset = [int] $offset; Size = [int] $size }
        }
        foreach ($required in @('#Pdb', '#~', '#Strings', '#GUID', '#Blob')) {
            if (-not $streams.ContainsKey($required)) { return $false }
        }
        $lastEnd = $cursor
        foreach ($stream in @($streams.Values | Sort-Object Offset)) {
            if ($stream.Offset -lt $lastEnd) { return $false }
            $lastEnd = $stream.Offset + $stream.Size
        }

        # Portable PDB #Pdb supplies referenced type-system row counts used by
        # coded indexes in the debug metadata tables.
        $rowCounts = [uint64[]]::new(64)
        $pdb = $streams['#Pdb']
        if ($pdb.Size -lt 32) { return $false }
        $referencedTables = [BitConverter]::ToUInt64($Bytes, $pdb.Offset + 24)
        $pdbCursor = $pdb.Offset + 32
        for ($table = 0; $table -lt 64; $table++) {
            if (($referencedTables -band ([uint64] 1 -shl $table)) -ne 0) {
                if ($pdbCursor + 4 -gt $pdb.Offset + $pdb.Size) { return $false }
                $rowCounts[$table] = [BitConverter]::ToUInt32($Bytes, $pdbCursor)
                $pdbCursor += 4
            }
        }
        if ($pdbCursor -ne $pdb.Offset + $pdb.Size) { return $false }

        $tables = $streams['#~']
        if ($tables.Size -lt 24) { return $false }
        $heapSizes = $Bytes[$tables.Offset + 6]
        $validTables = [BitConverter]::ToUInt64($Bytes, $tables.Offset + 8)
        $tableCursor = $tables.Offset + 24
        for ($table = 0; $table -lt 64; $table++) {
            if (($validTables -band ([uint64] 1 -shl $table)) -ne 0) {
                if ($table -lt 48 -or $table -gt 55 -or $tableCursor + 4 -gt $tables.Offset + $tables.Size) { return $false }
                $rowCounts[$table] = [BitConverter]::ToUInt32($Bytes, $tableCursor)
                $tableCursor += 4
            }
        }
        if (($validTables -band ([uint64] 1 -shl 55)) -eq 0) { return $false }

        $stringIndexSize = if (($heapSizes -band 0x01) -ne 0) { 4 } else { 2 }
        $guidIndexSize = if (($heapSizes -band 0x02) -ne 0) { 4 } else { 2 }
        $blobIndexSize = if (($heapSizes -band 0x04) -ne 0) { 4 } else { 2 }
        $tableIndexSize = @{}
        foreach ($table in @(0x06, 0x30, 0x32, 0x33, 0x34, 0x35)) {
            $tableIndexSize[$table] = if ($rowCounts[$table] -lt 65536) { 2 } else { 4 }
        }
        $hasCustomTables = @(0x06,0x04,0x01,0x02,0x08,0x09,0x0A,0x00,0x0E,0x17,0x14,0x11,0x1A,0x1B,0x20,0x23,0x26,0x27,0x28,0x2A,0x2C,0x2B,0x30,0x32,0x33,0x34,0x35)
        [uint64] $largestHasCustomTable = 0
        foreach ($table in $hasCustomTables) {
            if ($rowCounts[$table] -gt $largestHasCustomTable) { $largestHasCustomTable = $rowCounts[$table] }
        }
        $hasCustomIndexSize = if ($largestHasCustomTable -lt 2048) { 2 } else { 4 }

        $rowSizes = @{
            48 = $blobIndexSize + $guidIndexSize + $blobIndexSize + $guidIndexSize
            49 = $tableIndexSize[0x30] + $blobIndexSize
            50 = $tableIndexSize[0x06] + $tableIndexSize[0x35] + $tableIndexSize[0x33] + $tableIndexSize[0x34] + 8
            51 = 4 + $stringIndexSize
            52 = $stringIndexSize + $blobIndexSize
            53 = $tableIndexSize[0x35] + $blobIndexSize
            54 = $tableIndexSize[0x06] * 2
            55 = $hasCustomIndexSize + $guidIndexSize + $blobIndexSize
        }
        for ($table = 48; $table -lt 55; $table++) {
            [uint64] $tableBytes = $rowCounts[$table] * $rowSizes[$table]
            if ($tableBytes -gt (($tables.Offset + $tables.Size) - $tableCursor)) { return $false }
            $tableCursor += [int] $tableBytes
        }
        if ($rowCounts[55] -eq 0 -or $rowCounts[55] -gt 65536) { return $false }
        [uint64] $customDebugBytes = $rowCounts[55] * $rowSizes[55]
        if ($customDebugBytes -gt (($tables.Offset + $tables.Size) - $tableCursor)) { return $false }

        $guidHeap = $streams['#GUID']
        $blobHeap = $streams['#Blob']
        $sourceLinkGuidBytes = ([Guid] 'CC110556-A091-4D38-9FEC-25AB9A351A6A').ToByteArray()
        $sourceLinkJson = @()
        for ($row = 0; $row -lt $rowCounts[55]; $row++) {
            if ($tableCursor + $rowSizes[55] -gt $tables.Offset + $tables.Size) { return $false }
            $parent = if ($hasCustomIndexSize -eq 2) { [BitConverter]::ToUInt16($Bytes, $tableCursor) } else { [BitConverter]::ToUInt32($Bytes, $tableCursor) }
            $tableCursor += $hasCustomIndexSize
            $kind = if ($guidIndexSize -eq 2) { [BitConverter]::ToUInt16($Bytes, $tableCursor) } else { [BitConverter]::ToUInt32($Bytes, $tableCursor) }
            $tableCursor += $guidIndexSize
            $value = if ($blobIndexSize -eq 2) { [BitConverter]::ToUInt16($Bytes, $tableCursor) } else { [BitConverter]::ToUInt32($Bytes, $tableCursor) }
            $tableCursor += $blobIndexSize

            if ($kind -eq 0) { continue }
            [uint64] $guidOffset = $guidHeap.Offset + (($kind - 1) * 16)
            if ($guidOffset + 16 -gt $guidHeap.Offset + $guidHeap.Size) { return $false }
            $kindMatches = $true
            for ($byte = 0; $byte -lt 16; $byte++) {
                if ($Bytes[$guidOffset + $byte] -ne $sourceLinkGuidBytes[$byte]) { $kindMatches = $false; break }
            }
            if (-not $kindMatches) { continue }
            if ($parent -ne 39 -or $value -eq 0) { return $false }

            $blobOffset = $blobHeap.Offset + $value
            if ($blobOffset -ge $blobHeap.Offset + $blobHeap.Size) { return $false }
            $first = $Bytes[$blobOffset]
            if (($first -band 0x80) -eq 0) { $length = $first; $prefixLength = 1 }
            elseif (($first -band 0xC0) -eq 0x80) {
                if ($blobOffset + 2 -gt $blobHeap.Offset + $blobHeap.Size) { return $false }
                $length = (($first -band 0x3F) -shl 8) -bor $Bytes[$blobOffset + 1]; $prefixLength = 2
            }
            elseif (($first -band 0xE0) -eq 0xC0) {
                if ($blobOffset + 4 -gt $blobHeap.Offset + $blobHeap.Size) { return $false }
                $length = (($first -band 0x1F) -shl 24) -bor ($Bytes[$blobOffset + 1] -shl 16) -bor ($Bytes[$blobOffset + 2] -shl 8) -bor $Bytes[$blobOffset + 3]; $prefixLength = 4
            }
            else { return $false }
            if ($length -le 0 -or $length -gt 1048576 -or $blobOffset + $prefixLength + $length -gt $blobHeap.Offset + $blobHeap.Size) { return $false }
            $sourceLinkJson += [Text.Encoding]::UTF8.GetString($Bytes, $blobOffset + $prefixLength, $length)
        }
        $tableRemainder = ($tables.Offset + $tables.Size) - $tableCursor
        if ($tableRemainder -gt 4) { return $false }
        for ($padding = $tableCursor; $padding -lt $tables.Offset + $tables.Size; $padding++) {
            if ($Bytes[$padding] -ne 0) { return $false }
        }
        if ($sourceLinkJson.Count -ne 1) { return $false }

        try { $sourceLink = $sourceLinkJson[0] | ConvertFrom-Json }
        catch { return $false }
        if ($null -eq $sourceLink.PSObject.Properties['documents'] -or $null -eq $sourceLink.documents) { return $false }
        $mappings = @($sourceLink.documents.PSObject.Properties)
        if ($mappings.Count -eq 0 -or $mappings.Count -gt 128) { return $false }
        foreach ($mapping in $mappings) {
            $url = [string] $mapping.Value
            if ($mapping.Name.Length -gt 1024 -or $url.Length -gt 2048 -or
                -not $url.StartsWith($ExpectedSourceUrlPrefix, [StringComparison]::Ordinal) -or
                -not $url.Contains('*') -or $url.Contains('?') -or $url.Contains('#')) {
                return $false
            }
        }
        return $true
    }
    catch { return $false }
}

function Test-SymbolPackageContent {
    param(
        [Parameter(Mandatory)][string] $PrimaryPackagePath,
        [Parameter(Mandatory)][string] $SymbolPackagePath,
        [Parameter(Mandatory)][string] $Repository,
        [Parameter(Mandatory)][string] $SourceCommit
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $primary = [IO.Compression.ZipFile]::OpenRead($PrimaryPackagePath)
    $symbols = [IO.Compression.ZipFile]::OpenRead($SymbolPackagePath)
    try {
        $dlls = @($primary.Entries | Where-Object {
            -not [string]::IsNullOrEmpty($_.Name) -and $_.Name.EndsWith('.dll', [StringComparison]::Ordinal)
        })
        $pdbs = @($symbols.Entries | Where-Object {
            -not [string]::IsNullOrEmpty($_.Name) -and $_.Name.EndsWith('.pdb', [StringComparison]::Ordinal)
        })
        if ($dlls.Count -eq 0 -or $pdbs.Count -eq 0) {
            throw 'The package pair does not contain a complete managed symbol set.'
        }

        $allowedExtensions = @('.pdb', '.nuspec', '.xml', '.psmdcp', '.rels', '.p7s')
        foreach ($entry in $symbols.Entries | Where-Object { -not [string]::IsNullOrEmpty($_.Name) }) {
            $extension = if ($entry.Name -ceq '.rels') { '.rels' } else { [IO.Path]::GetExtension($entry.Name) }
            if ($extension -cnotin $allowedExtensions) {
                throw 'The symbol package contains an unsupported file type.'
            }
        }

        $dllPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($dll in $dlls) { $null = $dllPaths.Add($dll.FullName.Substring(0, $dll.FullName.Length - 4) + '.pdb') }
        $pdbPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($pdb in $pdbs) { $null = $pdbPaths.Add($pdb.FullName) }
        if ($dllPaths.Count -ne $pdbPaths.Count -or @($dllPaths | Where-Object { -not $pdbPaths.Contains($_) }).Count -ne 0) {
            throw 'The primary and symbol packages do not have matching assembly paths.'
        }

        $repositorySlug = $Repository.Substring('AtyaLibraries/'.Length)
        $sourceLinkUrlPrefix = "https://raw.githubusercontent.com/AtyaLibraries/$repositorySlug/$SourceCommit/"
        foreach ($pdb in $pdbs) {
            if ($pdb.Length -le 4 -or $pdb.Length -gt 67108864) {
                throw 'The symbol package contains an invalid Portable PDB.'
            }
            $stream = $pdb.Open()
            try {
                $memory = [IO.MemoryStream]::new()
                try {
                    $stream.CopyTo($memory)
                    $bytes = $memory.ToArray()
                }
                finally { $memory.Dispose() }
            }
            finally { $stream.Dispose() }
            if (-not (Test-PortablePdbSourceLinkBytes $bytes $sourceLinkUrlPrefix)) {
                throw 'The symbol package does not contain portable SourceLink-bound PDBs.'
            }
        }
    }
    finally {
        $symbols.Dispose()
        $primary.Dispose()
    }
}

function Test-CycloneDxPackageSbom {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $PackageId,
        [Parameter(Mandatory)][string] $Version,
        [Parameter(Mandatory)][string] $PackageSha256
    )

    try { $raw = [IO.File]::ReadAllText((Get-Item -LiteralPath $Path -ErrorAction Stop).FullName) }
    catch { throw 'The package SBOM is missing or unreadable.' }
    try { $sbom = $raw | ConvertFrom-Json }
    catch { throw 'The package SBOM is not valid JSON.' }
    $requiredTopLevel = @('$schema', 'bomFormat', 'specVersion', 'version', 'serialNumber', 'metadata')
    if (@($requiredTopLevel | Where-Object { $null -eq $sbom.PSObject.Properties[$_] }).Count -ne 0 -or
        $null -eq $sbom.metadata -or $null -eq $sbom.metadata.PSObject.Properties['component'] -or
        $null -eq $sbom.metadata.component -or
        $null -eq $sbom.metadata.component.PSObject.Properties['type'] -or
        $null -eq $sbom.metadata.component.PSObject.Properties['name'] -or
        $null -eq $sbom.metadata.component.PSObject.Properties['version']) {
        throw 'The package SBOM is missing required identity metadata.'
    }
    [int] $bomVersion = 0
    if (-not [int]::TryParse([string] $sbom.version, [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture, [ref] $bomVersion)) {
        throw 'The package SBOM uses an unsupported or ambiguous format version.'
    }
    $serial = [string] $sbom.serialNumber
    $serialGuid = [Guid]::Empty
    if (-not $serial.StartsWith('urn:uuid:', [StringComparison]::Ordinal) -or
        -not [Guid]::TryParse($serial.Substring('urn:uuid:'.Length), [ref] $serialGuid)) {
        throw 'The package SBOM uses an unsupported or ambiguous format version.'
    }
    if ([regex]::Matches($raw, '"bomFormat"\s*:').Count -ne 1 -or
        [regex]::Matches($raw, '"specVersion"\s*:').Count -ne 1 -or
        [string] $sbom.'$schema' -cne 'http://cyclonedx.org/schema/bom-1.6.schema.json' -or
        $sbom.bomFormat -cne 'CycloneDX' -or $sbom.specVersion -cne '1.6' -or $bomVersion -ne 1 -or
        [string] $sbom.metadata.component.type -cne 'file') {
        throw 'The package SBOM uses an unsupported or ambiguous format version.'
    }
    if ([string] $sbom.metadata.component.name -cne "$PackageId.$Version.nupkg" -or
        [string] $sbom.metadata.component.version -cne "sha256:$PackageSha256") {
        throw 'The package SBOM does not identify the validated primary package.'
    }
}

function New-ReleaseManifestText {
    param(
        [Parameter(Mandatory)][string] $PackageId,
        [Parameter(Mandatory)][string] $Version,
        [Parameter(Mandatory)][string] $Repository,
        [Parameter(Mandatory)][string] $SourceRef,
        [Parameter(Mandatory)][string] $SourceCommit,
        [Parameter(Mandatory)][string] $PolicyVersion,
        [Parameter(Mandatory)] $Files
    )

    $primaryHash = Get-Sha256Hex $Files['package.nupkg'].FullName
    $symbolHash = Get-Sha256Hex $Files['package.snupkg'].FullName
    $sbomHash = Get-Sha256Hex $Files['package.sbom.cdx.json'].FullName
    return (@(
        '{',
        '  "schemaVersion": "1.0.0",',
        "  `"packageId`": `"$PackageId`",",
        "  `"version`": `"$Version`",",
        "  `"repository`": `"$Repository`",",
        "  `"sourceRef`": `"$SourceRef`",",
        "  `"sourceCommit`": `"$SourceCommit`",",
        "  `"policyVersion`": `"$PolicyVersion`",",
        '  "artifacts": [',
        "    { `"name`": `"package.nupkg`", `"length`": $($Files['package.nupkg'].Length), `"sha256`": `"$primaryHash`" },",
        "    { `"name`": `"package.snupkg`", `"length`": $($Files['package.snupkg'].Length), `"sha256`": `"$symbolHash`" },",
        "    { `"name`": `"package.sbom.cdx.json`", `"length`": $($Files['package.sbom.cdx.json'].Length), `"sha256`": `"$sbomHash`" }",
        '  ]',
        '}'
    ) -join "`n") + "`n"
}

function New-SealedReleaseBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $BundlePath,
        [Parameter(Mandatory)][string] $RequestedRepository,
        [Parameter(Mandatory)][string] $RequestedVersion,
        [Parameter(Mandatory)][string] $RequestedRef,
        [Parameter(Mandatory)][string] $RequestedCommit,
        [Parameter(Mandatory)][string] $AllowlistPath,
        [long] $MaximumPackageBytes = 268435456,
        [long] $MaximumSbomBytes = 8388608,
        [long] $MaximumManifestBytes = 65536,
        [long] $MaximumAggregateBytes = 545325056
    )

    $release = ConvertTo-CanonicalReleaseRef $RequestedRef
    if ($release.Version -cne $RequestedVersion) { throw 'The requested tag and version do not agree.' }
    if ($RequestedCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'The requested source commit is missing or malformed.' }
    $files = Get-ReleaseBundleLayout $BundlePath -MaximumPackageBytes $MaximumPackageBytes `
        -MaximumSbomBytes $MaximumSbomBytes -MaximumManifestBytes $MaximumManifestBytes `
        -MaximumAggregateBytes $MaximumAggregateBytes
    $primary = Read-PackageIdentity $files['package.nupkg'].FullName -MaximumPackageBytes $MaximumPackageBytes
    $symbols = Read-PackageIdentity $files['package.snupkg'].FullName -MaximumPackageBytes $MaximumPackageBytes `
        -ExpectedExtension '.snupkg' -RequireSymbolsPackage
    if ($primary.PackageId -cne $symbols.PackageId -or $primary.Version -cne $symbols.Version -or
        $primary.Repository -cne $symbols.Repository -or $primary.SourceCommit -cne $symbols.SourceCommit) {
        throw 'The primary and symbol package identities do not agree.'
    }
    if ($primary.Version -cne $RequestedVersion) { throw 'The package version does not match the requested release tag.' }
    if ($primary.SourceCommit -cne $RequestedCommit) { throw 'The package source commit does not match the requested release tag.' }

    $policy = Read-PublisherAllowlist $AllowlistPath
    $authorization = Test-PackageAuthorization $primary $RequestedRepository $policy
    Test-SymbolPackageContent $files['package.nupkg'].FullName $files['package.snupkg'].FullName $authorization.Repository $RequestedCommit
    $primaryHash = Get-Sha256Hex $files['package.nupkg'].FullName
    Test-CycloneDxPackageSbom $files['package.sbom.cdx.json'].FullName $primary.PackageId $primary.Version $primaryHash

    $manifestPath = Join-Path (Get-Item -LiteralPath $BundlePath).FullName 'release-manifest.json'
    $manifest = New-ReleaseManifestText $primary.PackageId $primary.Version $authorization.Repository $release.Ref $RequestedCommit $authorization.PolicyVersion $files
    [IO.File]::WriteAllText($manifestPath, $manifest, [Text.UTF8Encoding]::new($false))
    $null = Test-SealedReleaseBundle $BundlePath $primary.PackageId $primary.Version $authorization.Repository `
        $release.Ref $RequestedCommit $authorization.PolicyVersion -MaximumPackageBytes $MaximumPackageBytes `
        -MaximumSbomBytes $MaximumSbomBytes -MaximumManifestBytes $MaximumManifestBytes `
        -MaximumAggregateBytes $MaximumAggregateBytes

    return [pscustomobject]@{
        PackageId = $primary.PackageId
        Version = $primary.Version
        Repository = $authorization.Repository
        SourceRef = $release.Ref
        SourceCommit = $RequestedCommit
        PolicyVersion = $authorization.PolicyVersion
        ManifestSha256 = Get-Sha256Hex $manifestPath
    }
}

function Test-SealedReleaseBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $BundlePath,
        [Parameter(Mandatory)][string] $ExpectedPackageId,
        [Parameter(Mandatory)][string] $ExpectedVersion,
        [Parameter(Mandatory)][string] $ExpectedRepository,
        [Parameter(Mandatory)][string] $ExpectedRef,
        [Parameter(Mandatory)][string] $ExpectedCommit,
        [Parameter(Mandatory)][string] $ExpectedPolicyVersion,
        [long] $MaximumPackageBytes = 268435456,
        [long] $MaximumSbomBytes = 8388608,
        [long] $MaximumManifestBytes = 65536,
        [long] $MaximumAggregateBytes = 545325056
    )

    $files = Get-ReleaseBundleLayout $BundlePath -IncludeManifest -MaximumPackageBytes $MaximumPackageBytes `
        -MaximumSbomBytes $MaximumSbomBytes -MaximumManifestBytes $MaximumManifestBytes `
        -MaximumAggregateBytes $MaximumAggregateBytes
    $manifestRaw = [IO.File]::ReadAllText($files['release-manifest.json'].FullName)
    try { $manifest = $manifestRaw | ConvertFrom-Json }
    catch { throw 'The release manifest is not valid JSON.' }
    $requiredManifestFields = @('schemaVersion', 'packageId', 'version', 'repository', 'sourceRef', 'sourceCommit', 'policyVersion', 'artifacts')
    if (@($requiredManifestFields | Where-Object { $null -eq $manifest.PSObject.Properties[$_] }).Count -ne 0) {
        throw 'The release manifest is missing required metadata.'
    }
    if ($manifest.schemaVersion -cne '1.0.0') { throw 'The release manifest uses an unsupported schema version.' }
    if ($manifest.packageId -cne $ExpectedPackageId -or $manifest.version -cne $ExpectedVersion -or
        $manifest.repository -cne $ExpectedRepository -or $manifest.sourceRef -cne $ExpectedRef -or
        $manifest.sourceCommit -cne $ExpectedCommit -or
        $manifest.policyVersion -cne $ExpectedPolicyVersion) {
        throw 'The release manifest identity does not match the authorized release.'
    }

    $artifacts = @($manifest.artifacts)
    if ($artifacts.Count -ne 3) { throw 'The release manifest contains an invalid artifact set.' }
    foreach ($name in @('package.nupkg', 'package.snupkg', 'package.sbom.cdx.json')) {
        $entry = @($artifacts | Where-Object { $null -ne $_.PSObject.Properties['name'] -and [string] $_.name -ceq $name })
        [long] $recordedLength = 0
        $entryShapeValid = $entry.Count -eq 1 -and $null -ne $entry[0].PSObject.Properties['length'] -and
            $null -ne $entry[0].PSObject.Properties['sha256'] -and
            [long]::TryParse([string] $entry[0].length, [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture, [ref] $recordedLength)
        if (-not $entryShapeValid -or $recordedLength -ne $files[$name].Length -or
            [string] $entry[0].sha256 -cne (Get-Sha256Hex $files[$name].FullName)) {
            throw 'A sealed artifact hash or length does not match the release manifest.'
        }
    }

    $expectedManifest = New-ReleaseManifestText $ExpectedPackageId $ExpectedVersion $ExpectedRepository $ExpectedRef $ExpectedCommit $ExpectedPolicyVersion $files
    if ($manifestRaw -cne $expectedManifest) { throw 'The release manifest is not in deterministic canonical form.' }
    return $true
}

Export-ModuleMember -Function ConvertTo-CanonicalRepository, ConvertTo-CanonicalReleaseRef,
    ConvertTo-SafeRelativePath, ConvertFrom-PackageRepositoryUrl, Read-PackageIdentity,
    Read-PublisherAllowlist, Test-PackageAuthorization, New-SealedReleaseBundle,
    Test-SealedReleaseBundle
