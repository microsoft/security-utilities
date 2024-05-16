<#
.SYNOPSIS
    Build, test, and package the Microsoft.Security.Tools.Internal code base
.DESCRIPTION
    Builds the Microsoft.Security.Tools.Internal solution for multiple target frameworks, runs tests, and creates
    NuGet packages.
.PARAMETER Configuration
    The build configuration: Release or Debug. Default=Release
.PARAMETER NoBuild
    Do not build.
.PARAMETER NoTest
    Do not run tests.
.PARAMETER NoFormat
    Do not format files based on dotnet-format tool.
.PARAMETER EnableCoverage
    Enable CodeCoverage.
#>

[CmdletBinding()]
param(
    [string]
    [ValidateSet("Debug", "Release")]
    $Configuration="Release",

    [switch]
    $NoBuild,

    [switch]
    $NoTest,
    
    [switch]
    $NoFormat,

    [switch]
    $EnableCoverage,

    [switch]
    $NoDiffCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"

$ScriptName = $([io.Path]::GetFileNameWithoutExtension($PSCommandPath))
$RepoRoot = $(Resolve-Path $PSScriptRoot\..).Path

function Exit-WithFailureMessage($scriptName, $message) {
    Write-Information "${scriptName}: $message"
    Write-Information "$scriptName FAILED."
    exit 1
}

If (Test-Path "..\bld") {
    Write-Information "Deleting old build..."
    rd /s /q ..\bld
}

if (-not $NoBuild) {
    Write-Information "Building Microsoft.Security.Utilities.sln (dotnet)..."
    dotnet build $RepoRoot\src\Microsoft.Security.Utilities.sln -c $Configuration -p:Deterministic=true -p:WarningsAsErrors="MSB3277"
    if ($LASTEXITCODE -ne 0) {
        Exit-WithFailureMessage $ScriptName "Build of \Microsoft.Security.Utilities failed."
    }
}

if (-not $NoTest) {
    Write-Information "Running tests..."

    $CodeCoverageCommand = '--collect:"Code Coverage"'
    if (-not $EnableCoverage) {
        $CodeCoverageCommand = ""
    }

    dotnet test $RepoRoot\src\Microsoft.Security.Utilities.sln -c $Configuration --logger trx --no-build $CodeCoverageCommand /p:IncludeTestAssembly=false
    if ($LASTEXITCODE -ne 0) {
        Exit-WithFailureMessage $ScriptName "Test of \Microsoft.Security.Utilities failed."
    }
}

Write-Information "Creating packages.."
cmd.exe /c 'BuildPackages.cmd'
if ($LASTEXITCODE -ne 0) {
    Exit-WithFailureMessage $ScriptName "Package build failed."
}

Write-Information "$ScriptName SUCCEEDED."
