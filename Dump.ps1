$output = @()
$vulnConnectors = @("connector_base", "excelonlinebusiness", "github", "gmail", "keyvault", "shared_azureblob", "shared_azurequeues", "shared_azuretables", "shared_documentdb", "shared_sql")
foreach($app in Get-AdminPowerApp){
    $owner = $app.Owner.displayName
    $appName = $app.AppName
    $appDisplayName = $app.DisplayName
    $envName = $app.EnvironmentName
    $vulnerable = $false
    foreach($principal in (Get-AdminPowerAppRoleAssignment -AppName $appName -EnvironmentName $envName)){
        if($principal.PrincipalDisplayName -eq "Jeder"){
            $vulnerable = $true
            break
        }
    }
    if(!$vulnerable){
        continue
    }
    $connectors = @()
    foreach($connector in (Get-AdminPowerAppConnection -EnvironmentName $app.EnvironmentName)){
        if($connector.ConnectorName -in $vulnConnectors){
            $connectors += $connector
        }
    }
    Write-Host $connectors
}