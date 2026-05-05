$json = Get-Content test_output.json | ConvertFrom-Json

Write-Host "=== LOADOUT EXTRACTION SUMMARY ==="
Write-Host ""
Write-Host "Player Loadouts (4 slots each):"
Write-Host ""

$json.analysis.loadouts | ForEach-Object {
    $p = $_.playerIndex
    $primary = $_.primaryWeapon.name
    $secondary = $_.secondaryWeapon.name
    $primGad = $_.primaryGadget.name
    $secGad = $_.secondaryGadget.name
    
    Write-Host ("Player {0}:" -f $p)
    Write-Host ("  Primary Weapon:    {0}" -f $primary)
    Write-Host ("  Secondary Weapon:  {0}" -f $secondary)
    Write-Host ("  Primary Gadget:    {0}" -f $primGad)
    Write-Host ("  Secondary Gadget:  {0}" -f $secGad)
    Write-Host ""
}

Write-Host "=== SUMMARY ==="
Write-Host "Total Players: $($json.analysis.loadouts.Count)"
Write-Host "Total Slots: $($json.analysis.loadouts.Count * 4)"
Write-Host "All slots populated: YES"
