# ============================================================
# 02_OpenSSL.ps1
#
# PKI Script - OpenSSL Helper
#
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
#
# Purpose:
#   - Locate OpenSSL
#   - Initialize OpenSSL
#   - Execute OpenSSL safely
#   - Normalize Unicode PKI naming to ASCII
#   - Provide ASCII-safe PKI values for OpenSSL
#
# IMPORTANT:
#   PowerShell may pass Unicode command-line arguments to
#   OpenSSL incorrectly depending on the OpenSSL/Windows
#   process boundary and encoding.
#
#   Therefore:
#
#       Original:
#           Agantra Inovatif OÜ
#
#       OpenSSL-safe:
#           Agantra Inovatif OU
#
#   The original Unicode value is preserved.
#   OpenSSL-facing values are available through:
#
#       $script:Pki.AuthorAscii
#       $script:Pki.CompanyAscii
#       $script:Pki.EmailAscii
#
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


# ============================================================
# Convert Unicode Text To ASCII
# ============================================================
function ConvertTo-Ascii {

    <#
    .SYNOPSIS
        Converts Unicode text to the closest ASCII representation.

    .DESCRIPTION
        Uses Unicode FormD normalization to separate base
        characters from combining marks.

        Example:

            Ü
             |
             +-- U
             +-- combining diaeresis

        The combining mark is removed:

            Ü -> U

        Additional Unicode characters that do not decompose
        through FormD are handled using Unicode code points.

    .EXAMPLES

        ConvertTo-Ascii 'Agantra Inovatif OÜ'

        Result:
            Agantra Inovatif OU

        ConvertTo-Ascii 'München'

        Result:
            Munchen

        ConvertTo-Ascii 'François'

        Result:
            Francois

        ConvertTo-Ascii 'José García'

        Result:
            Jose Garcia
    #>

    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )


    # --------------------------------------------------------
    # Empty value
    # --------------------------------------------------------
    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }


    # --------------------------------------------------------
    # Unicode FormD normalization
    # --------------------------------------------------------
    #
    # Example:
    #
    #   Ü
    #
    # becomes:
    #
    #   U + combining diaeresis
    #
    # The combining mark is removed below.
    # --------------------------------------------------------
    $normalized = $Text.Normalize(
        [System.Text.NormalizationForm]::FormD
    )


    # --------------------------------------------------------
    # Remove combining marks
    # --------------------------------------------------------
    $builder = [System.Text.StringBuilder]::new()


    foreach ($char in $normalized.ToCharArray()) {

        $category =
            [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory(
                $char
            )


        if (
            $category -ne
                [System.Globalization.UnicodeCategory]::NonSpacingMark -and

            $category -ne
                [System.Globalization.UnicodeCategory]::SpacingCombiningMark -and

            $category -ne
                [System.Globalization.UnicodeCategory]::EnclosingMark
        ) {

            [void]$builder.Append($char)
        }
    }


    $result = $builder.ToString()


    # ========================================================
    # Unicode characters which do not decompose using FormD
    # ========================================================
    #
    # IMPORTANT:
    #
    # Do NOT put Unicode characters directly in a PowerShell
    # hashtable.
    #
    # Use hexadecimal Unicode code points instead.
    #
    # This prevents source-file encoding/parser problems.
    # ========================================================


    # --------------------------------------------------------
    # Æ -> AE
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x00C6,
        'AE'
    )


    # --------------------------------------------------------
    # æ -> ae
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x00E6,
        'ae'
    )


    # --------------------------------------------------------
    # Œ -> OE
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0152,
        'OE'
    )


    # --------------------------------------------------------
    # œ -> oe
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0153,
        'oe'
    )


    # --------------------------------------------------------
    # Ø -> O
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x00D8,
        'O'
    )


    # --------------------------------------------------------
    # ø -> o
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x00F8,
        'o'
    )


    # --------------------------------------------------------
    # Ð -> D
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x00D0,
        'D'
    )


    # --------------------------------------------------------
    # ð -> d
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x00F0,
        'd'
    )


    # --------------------------------------------------------
    # Þ -> TH
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x00DE,
        'TH'
    )


    # --------------------------------------------------------
    # þ -> th
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x00FE,
        'th'
    )


    # --------------------------------------------------------
    # Ł -> L
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0141,
        'L'
    )


    # --------------------------------------------------------
    # ł -> l
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0142,
        'l'
    )


    # --------------------------------------------------------
    # Đ -> D
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0110,
        'D'
    )


    # --------------------------------------------------------
    # đ -> d
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0111,
        'd'
    )


    # --------------------------------------------------------
    # Ħ -> H
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0126,
        'H'
    )


    # --------------------------------------------------------
    # ħ -> h
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0127,
        'h'
    )


    # --------------------------------------------------------
    # Ŧ -> T
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0166,
        'T'
    )


    # --------------------------------------------------------
    # ŧ -> t
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x0167,
        't'
    )


    # --------------------------------------------------------
    # ß -> ss
    # --------------------------------------------------------
    $result = $result.Replace(
        [string][char]0x00DF,
        'ss'
    )


    # ========================================================
    # Final ASCII-only filtering
    # ========================================================
    $asciiBuilder =
        [System.Text.StringBuilder]::new()


    foreach ($char in $result.ToCharArray()) {

        $codePoint = [int][char]$char


        if ($codePoint -le 127) {

            [void]$asciiBuilder.Append($char)
        }
    }


    return $asciiBuilder.ToString()
}


# ============================================================
# Get OpenSSL-Safe Value
# ============================================================
function Get-PkiOpenSslValue {

    <#
    .SYNOPSIS
        Converts a PKI value to an ASCII-safe OpenSSL value.
    #>

    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )


    return ConvertTo-Ascii -Text $Value
}


# ============================================================
# Get PKI ASCII Name
# ============================================================
function Get-PkiAsciiName {

    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )


    return ConvertTo-Ascii -Text $Value
}


# ============================================================
# Find OpenSSL
# ============================================================
function Find-OpenSSL {

    # --------------------------------------------------------
    # First try PATH
    # --------------------------------------------------------
    $commands = @(
        'openssl.exe',
        'openssl'
    )


    foreach ($name in $commands) {

        $cmd =
            Get-Command `
                $name `
                -ErrorAction SilentlyContinue


        if ($null -ne $cmd) {

            return $cmd.Source
        }
    }


    # --------------------------------------------------------
    # Common Windows installation locations
    # --------------------------------------------------------
    $commonPaths = @(
        'C:\Program Files\OpenSSL-Win64\bin\openssl.exe',
        'C:\Program Files\OpenSSL\bin\openssl.exe',
        'C:\Program Files\OpenSSL-Win32\bin\openssl.exe',
        'C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe'
    )


    foreach ($path in $commonPaths) {

        if (
            Test-Path `
                -LiteralPath $path `
                -PathType Leaf
        ) {

            return $path
        }
    }


    # --------------------------------------------------------
    # OpenSSL not found
    # --------------------------------------------------------
    throw @"
OpenSSL executable was not found.

Please install OpenSSL and ensure that openssl.exe
is available in the PATH environment variable.

Common installation paths checked:

$($commonPaths -join "`n")
"@
}


# ============================================================
# Initialize OpenSSL
# ============================================================
function Initialize-OpenSSL {

    # --------------------------------------------------------
    # Locate OpenSSL
    # --------------------------------------------------------
    $script:Pki.OpenSslExe =
        Find-OpenSSL


    Write-PkiVerbose (
        "OpenSSL executable: " +
        $script:Pki.OpenSslExe
    )


    # --------------------------------------------------------
    # Get OpenSSL version
    # --------------------------------------------------------
    $versionResult =
        Invoke-OpenSSL `
            -Arguments @('version') `
            -CaptureOutput


    $script:Pki.OpenSslVersion =
        $versionResult.StdOut.Trim()


    Write-PkiLog (
        "OpenSSL: " +
        $script:Pki.OpenSslVersion
    )
}


# ============================================================
# Initialize PKI ASCII Names
# ============================================================
function Initialize-PkiAsciiNames {

    <#
    .SYNOPSIS
        Creates ASCII-safe PKI values.

    .DESCRIPTION
        Original values are preserved.

        Example:

            Company
                Agantra Inovatif OÜ

            CompanyUnicode
                Agantra Inovatif OÜ

            CompanyAscii
                Agantra Inovatif OU

        Certificate generation code should use the *Ascii
        properties when passing values to OpenSSL.
    #>


    # --------------------------------------------------------
    # Ensure Pki object exists
    # --------------------------------------------------------
    if ($null -eq $script:Pki) {

        throw (
            'The $script:Pki object has not been initialized.'
        )
    }


    # --------------------------------------------------------
    # Default Author
    # --------------------------------------------------------
    if (-not $script:Pki.ContainsKey('Author')) {

        $script:Pki.Author =
            'Nicko Satria Utama'
    }


    # --------------------------------------------------------
    # Default Company
    # --------------------------------------------------------
    if (-not $script:Pki.ContainsKey('Company')) {

        $script:Pki.Company =
            'Agantra Inovatif OÜ'
    }


    # --------------------------------------------------------
    # Default Email
    # --------------------------------------------------------
    if (-not $script:Pki.ContainsKey('Email')) {

        $script:Pki.Email =
            'nicko@nextmantra.com'
    }


    # ========================================================
    # Preserve original Unicode values
    # ========================================================

    $script:Pki.AuthorUnicode =
        [string]$script:Pki.Author


    $script:Pki.CompanyUnicode =
        [string]$script:Pki.Company


    $script:Pki.EmailUnicode =
        [string]$script:Pki.Email


    # ========================================================
    # Generate ASCII-safe values
    # ========================================================

    $script:Pki.AuthorAscii =
        ConvertTo-Ascii `
            -Text $script:Pki.AuthorUnicode


    $script:Pki.CompanyAscii =
        ConvertTo-Ascii `
            -Text $script:Pki.CompanyUnicode


    $script:Pki.EmailAscii =
        ConvertTo-Ascii `
            -Text $script:Pki.EmailUnicode


    # ========================================================
    # Logging
    # ========================================================

    Write-PkiVerbose (
        'PKI Author Unicode: ' +
        $script:Pki.AuthorUnicode
    )


    Write-PkiVerbose (
        'PKI Author ASCII  : ' +
        $script:Pki.AuthorAscii
    )


    Write-PkiVerbose (
        'PKI Company Unicode: ' +
        $script:Pki.CompanyUnicode
    )


    Write-PkiVerbose (
        'PKI Company ASCII  : ' +
        $script:Pki.CompanyAscii
    )


    Write-PkiVerbose (
        'PKI Email Unicode: ' +
        $script:Pki.EmailUnicode
    )


    Write-PkiVerbose (
        'PKI Email ASCII  : ' +
        $script:Pki.EmailAscii
    )
}


# ============================================================
# Validate / Prepare OpenSSL Subject Value
# ============================================================
function ConvertTo-PkiOpenSslSubject {

    <#
    .SYNOPSIS
        Converts a certificate subject component to ASCII.

    .DESCRIPTION
        This should be used by certificate-generation functions
        before constructing OpenSSL subject strings.

    Example:

        ConvertTo-PkiOpenSslSubject `
            'Agantra Inovatif OÜ (NextMantra)'

    Result:

        Agantra Inovatif OU (NextMantra)
    #>

    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )


    return ConvertTo-Ascii -Text $Value
}


# ============================================================
# Invoke OpenSSL
# ============================================================
function Invoke-OpenSSL {

    <#
    .SYNOPSIS
        Executes OpenSSL safely.

    .DESCRIPTION
        Uses System.Diagnostics.Process and ArgumentList.

        ArgumentList avoids manual command-line quoting problems
        involving spaces and special characters.
    #>

    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [switch]$CaptureOutput
    )


    # --------------------------------------------------------
    # Validate OpenSSL executable
    # --------------------------------------------------------
    Assert-PkiFile `
        -Path $script:Pki.OpenSslExe


    # --------------------------------------------------------
    # Prepare safe debug representation
    # --------------------------------------------------------
    $displayArguments = @(
        foreach ($argument in $Arguments) {

            if ($argument -match '^pass(out|in)$') {

                '[PASSWORD]'
            }
            else {

                $argument
            }
        }
    )


    Write-PkiVerbose (
        'OpenSSL command: openssl.exe ' +
        ($displayArguments -join ' ')
    )


    # ========================================================
    # Process configuration
    # ========================================================

    $psi =
        [System.Diagnostics.ProcessStartInfo]::new()


    $psi.FileName =
        $script:Pki.OpenSslExe


    foreach ($argument in $Arguments) {

        [void]$psi.ArgumentList.Add(
            [string]$argument
        )
    }


    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true


    # ========================================================
    # Execute process
    # ========================================================

    $process =
        [System.Diagnostics.Process]::new()


    $process.StartInfo =
        $psi


    $stdout = ''
    $stderr = ''
    $exitCode = -1


    try {

        [void]$process.Start()


        $stdout =
            $process.StandardOutput.ReadToEnd()


        $stderr =
            $process.StandardError.ReadToEnd()


        $process.WaitForExit()


        $exitCode =
            $process.ExitCode
    }
    finally {

        $process.Dispose()
    }


    # ========================================================
    # Handle OpenSSL failure
    # ========================================================

    if ($exitCode -ne 0) {

        $details =
            "OpenSSL exited with code $exitCode."


        if (
            -not [string]::IsNullOrWhiteSpace($stderr)
        ) {

            $details += (
                "`nSTDERR:`n" +
                $stderr.Trim()
            )
        }


        if (
            -not [string]::IsNullOrWhiteSpace($stdout)
        ) {

            $details += (
                "`nSTDOUT:`n" +
                $stdout.Trim()
            )
        }


        throw $details
    }


    # ========================================================
    # Return output
    # ========================================================

    if ($CaptureOutput) {

        return [pscustomobject]@{
            ExitCode = $exitCode
            StdOut   = $stdout
            StdErr   = $stderr
        }
    }


    return $stdout
}


# ============================================================
# END OF 02_OpenSSL.ps1
# ============================================================