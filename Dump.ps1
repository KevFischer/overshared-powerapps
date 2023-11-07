$output = @()
$vulnConnectors = @("shared_excelonlinebusiness","shared_github", "shared_gmail", "shared_keyvault", "shared_azureblob", "shared_azurequeues", "shared_azuretables", "shared_documentdb", "shared_sql")
foreach($env in Get-AdminPowerAppEnvironment){
    foreach($app in Get-AdminPowerApp -EnvironmentName $env.EnvironmentName){
        $vulnerable = $false
        foreach($principal in (Get-AdminPowerAppRoleAssignment -AppName $app.AppName -EnvironmentName $app.EnvironmentName)){
            if(($principal.PrincipalType -eq "Tenant")){
                $vulnerable = $true
                break
            }
        }
        if(!$vulnerable){continue}
        $connectors = @()
        foreach($connector in (Get-AdminPowerAppConnection -EnvironmentName $app.EnvironmentName)){
            if($connector.ConnectorName -in $vulnConnectors){
                $connectors += $connector.ConnectorName
            }
        }
        if($connectors.Count -eq 0){continue}
        $output += @{
            AppDisplayName = $app.DisplayName
            AppName = $app.AppName
            EnvironmentName = $app.EnvironmentName
            Owner = $app.Owner.displayName
            Connections = $connectors
        }
    }
}
$output = $output | ConvertTo-Json -Compress | ConvertFrom-Json
$output | Format-Table -AutoSize
$output | Format-Table -AutoSize | Out-File o.txt
