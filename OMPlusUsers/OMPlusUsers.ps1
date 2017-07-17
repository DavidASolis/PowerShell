<#
.Synopsis
   Export all user's pager field numbers for import into OMPlus systems in DLA regions
.DESCRIPTION
   Export all user's pager field numbers for import into OMPlus systems in DLA regions. Pager fields are filled in with user's badge number for secure printing.

   Requires: Windows PowerShell Module for Active Directory
#>
$domains = "int.dci.discovery.com","us.dci.discovery.com","dna.dci.discovery.com","us.dci.discovery.com","dne.dci.discovery.com"
$users = @()
$destinations = "mexzpprint01","bogzpprint01","buezpprint01","splzpprint01"
$export

Foreach($domain in $domains)
{
$users += get-aduser -server $domain -filter {(Enabled -eq $true)} -Properties Pager, SamAccountName |`
		where pager -ne $null |`
        Select-Object Pager,SamAccountName |`
}
$users | Sort-Object Pager | ConvertTo-Csv -NoTypeInformation | % { $_ -replace '"', ""} | Out-File $env:temp\cardusers

#Copy cardusers file to all servers defined in destination variable
Foreach($destination in $destinations)
{
    Copy-Item $env:temp\cardusers \\$destination\c$\Plustech\OMUtils\PrintReleaseFiles
}

#Cleanup of temp location
Remove-Item $env:temp\cardusers
