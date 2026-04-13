$path = ".\passwords.json"
 
# Hardcoded key — replace with your actual 32-char key
$keyRaw = "FoxtrotTeamKeyForBlueTeam26cday1"
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($keyRaw.PadRight(32).Substring(0, 32))

if (-not (Test-Path $path)) {
    Write-Host "passwords.json not found at $path" -ForegroundColor Red
    exit
}

Write-Host "--------------------------------"
Write-Host "| ~ $($PSStyle.Bold)PASSWORD PRINTING SCRIPT$($PSStyle.Reset) ~ |"
Write-Host "| $($PSStyle.Italic)don't push this file to main$($PSStyle.Reset) |"
Write-Host "--------------------------------"
Write-Host ""
Write-Host "Private Key:"
Write-Host "`t$keyRaw"
Write-Host ""
Write-Host "Passwords:"

 
$data = Get-Content $path -Raw | ConvertFrom-Json
 
foreach ($user in $data.PSObject.Properties) {
    $securePassword = $user.Value.encrypted | ConvertTo-SecureString -Key $keyBytes
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try {
        $plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        Write-Host "`t$($user.Name) : $plaintext"
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}