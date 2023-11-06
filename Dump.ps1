$output = @()
$vulnConnectors = @("connector_base", "excelonlinebusiness","shared_github" ,"github", "gmail", "keyvault", "shared_azureblob", "shared_azurequeues", "shared_azuretables", "shared_documentdb", "shared_sql")
foreach($app in Get-AdminPowerApp){
    $owner = $app.Owner.displayName
    $appName = $app.AppName
    $appDisplayName = $app.DisplayName
    $envName = $app.EnvironmentName
    $vulnerable = $false
    $sharedWith = @()
    foreach($principal in (Get-AdminPowerAppRoleAssignment -AppName $appName -EnvironmentName $envName)){
        $sharedWith += $principal.PrincipalDisplayName
        if(($principal.PrincipalDisplayName -eq "Jeder") -or ($principal.PrincipalDisplayName -eq "Everyone")){
            $vulnerable = $true
            break
        }
    }
    if(!$vulnerable){
        continue
    }
    $connectors = @()
    foreach($connector in (Get-AdminPowerAppConnection -EnvironmentName $app.EnvironmentName)){
        Write-Host $connector.ConnectorName
        if($connector.ConnectorName -in $vulnConnectors){
            $connectors += $connector.ConnectorName
        }
    }
    $output += @{
        AppDisplayName = $appDisplayName
        AppName = $appName
        EnvironmentName = $envName
        Owner = $owner
        SharedWith = $sharedWith
        Connections = $connectors
    }
}
$output = $output | ConvertTo-Json -Compress | ConvertFrom-Json
$output | Format-Table -AutoSize | Out-File o.txt
