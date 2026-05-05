$json = Get-Content test_output.json | ConvertFrom-Json
$total = 0
$resolved = 0
$unresolved = @()

$json.analysis.loadouts | ForEach-Object {
    $_.primaryWeapon, $_.secondaryWeapon, $_.primaryGadget, $_.secondaryGadget | ForEach-Object {
        if ($_.name -notmatch '^0x') {
            $resolved++
        } else {
            $unresolved += $_.gameId
        }
        $total++
    }
}

Write-Host "Name Resolution Stats:"
Write-Host "Resolved: $resolved/$total ($([math]::Round($resolved/$total*100, 1))%)"
Write-Host ""
Write-Host "Unresolved IDs (hex):"
$unresolved | Sort-Object -Unique | ForEach-Object {
    Write-Host "  0x$($_.ToString('X'))"
}
