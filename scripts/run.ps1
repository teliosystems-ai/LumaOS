[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $LumaArguments
)

$ErrorActionPreference = "Stop"
$ProjectDirectory = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$CliPath = Join-Path $ProjectDirectory "src\luma_os\cli.py"

if (-not (Test-Path -LiteralPath $CliPath -PathType Leaf)) {
    throw "Luma OS source is incomplete: src/luma_os/cli.py was not found."
}

& $Python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "Luma OS requires Python 3.11 or newer."
}

$PreviousPythonPath = $env:PYTHONPATH
try {
    $SourcePath = Join-Path $ProjectDirectory "src"
    $env:PYTHONPATH = if ($PreviousPythonPath) {
        "$SourcePath$([IO.Path]::PathSeparator)$PreviousPythonPath"
    } else {
        $SourcePath
    }
    Set-Location -LiteralPath $ProjectDirectory
    if (-not $LumaArguments -or $LumaArguments.Count -eq 0) {
        $LumaArguments = @("serve")
    }
    & $Python -m luma_os.cli @LumaArguments
    exit $LASTEXITCODE
} finally {
    $env:PYTHONPATH = $PreviousPythonPath
}
