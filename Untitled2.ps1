Import-module ActiveDirectory 
-whatif
$domain = Thompsonshotel.nl
$group = Import-Csv -delimiter ";" -Path "C:\Scripts\groepen.csv" 
#create active directory groups
 
ForEach ($item In $group) 
    { 
        $create_group = New-ADGroup -Name $item.GroupName -GroupCategory $item.GroupCategory -groupScope $item.GroupScope
        Write-Host -ForegroundColor Green "Group $($item.GroupName) created!" 
    }
#add users to active directory groups
$group | % 
if($user.user = $user){} ForEach ($user in $group){Get-ADUser $item.GroupName -Group pCategory $item.GroupCategory  $group.user -identity $group Add-ADGroupMember -Member $_.UserName}
else {write-host -ForegroundColor Red  "in prut not not valid"}

#create active directory groups folder on D drive

ForEach ($item In $group)
    { 
        $create_group = New-Item -ItemType directory -Path D:\$domain\$Group -Name $item.GroupName -GroupCategory $item.GroupCategory -groupScope Global.GroupScope
        Write-Host -ForegroundColor Green "Folder $($item.GroupName) created!" 
    }
#add permissions on active directory groups folder on D drive
 (ForEach item in -Path D:\$domain ($grouppermission)
    { 
        $Acl = Get-Acl "D:\$domain"
        $Ar = New-Object  system.security.accesscontrol.filesystemaccessrule("$group","Write","Read","execute","Allow")
        $Acl.SetAccessRule($Ar)
        Set-Acl "C:\$domain\$group" $Acl
        Write-Host -ForegroundColor Green "permissions $($item.GroupName) added!" 
    }  
    else 
    { Write-Host -ForegroundColor Red "permissions $($item.GroupName) failed" }













