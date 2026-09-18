<#
.SYNOPSIS
Windows alternative for the primary Linux start.sh launcher.

.DESCRIPTION
Translates the repository path for WSL and delegates all startup behavior to
start.sh. Press Ctrl+C to stop the server.

.PARAMETER Port
The localhost port used by the demo server. Defaults to 4173.

.PARAMETER Install
Asks start.sh to refresh npm dependencies before starting.
#>
[CmdletBinding()]
param(
  [ValidateRange(1, 65535)]
  [int]$Port = 4173,

  [switch]$Install
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-BashLiteral {
  param([Parameter(Mandatory)][string]$Value)

  $singleQuote = [string][char]39
  $doubleQuote = [string][char]34
  $escapedSingleQuote =
    $singleQuote + $doubleQuote + $singleQuote + $doubleQuote + $singleQuote
  return $singleQuote + $Value.Replace($singleQuote, $escapedSingleQuote) + $singleQuote
}

if ($null -eq (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  throw "WSL is required. Install Ubuntu WSL or run start.sh directly on Linux."
}

$wslRepositoryRoot = (& wsl.exe wslpath -a -- $PSScriptRoot).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($wslRepositoryRoot)) {
  throw "Could not translate the repository path for WSL."
}

$quotedRepositoryRoot = ConvertTo-BashLiteral $wslRepositoryRoot
$installArgument = if ($Install) { " --install" } else { "" }
$command =
  "cd $quotedRepositoryRoot && bash ./start.sh --port $Port$installArgument"

& wsl.exe bash -lic $command
$exitCode = $LASTEXITCODE
$wasInterrupted = $exitCode -in 2, 130
if ($exitCode -ne 0 -and -not $wasInterrupted) {
  throw "Linux startup script failed with exit code $exitCode."
}
