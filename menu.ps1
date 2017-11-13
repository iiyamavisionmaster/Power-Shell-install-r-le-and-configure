  function DossierCreation(){


  Set-Location "C:\Users\Administrateur\Desktop"
    $temp=New-Item -Name "dossier" -ItemType directory
    $acl = Get-Acl $temp
  $permission = "ILARIA.LAN\Direction","Readonly","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp
$permission = "ILARIA.LAN\Informatique","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp




  Set-Location "C:\Users\Administrateur\Desktop\dossier"
  $temp=New-Item -Name "INFORMATIQUE" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\INFORMATIQUE","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp



  $temp=New-Item -Name "SAV" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\SAV","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp



  $temp=New-Item -Name "DIRECTION" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\DIRECTION","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp



  $temp=New-Item -Name "PRODUIT A" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\PRODUITA","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp



  $temp=New-Item -Name "PRODUIT B" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\PRODUITB","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp



  $temp=New-Item -Name "ADMINISTRATIF" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\ADMINISTRATIF","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp







  $users = Import-Csv -Path 'C:\Users\Administrateur\Desktop\T_UTILISATEUR.csv' -Delimiter ";"
  foreach ($user in $users) {
  $nom="$($user.NOM)"
  $service="$($user.SERVICE)"



  if ($service -eq "PRODUIT A"){ 
  Set-Location "C:\Users\Administrateur\Desktop\dossier\$service"
  $temp=New-Item -Name "$nom" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\$nom","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp
  } 
  if ($service -eq "PRODUIT B"){ 
    Set-Location "C:\Users\Administrateur\Desktop\dossier\$service"
    $temp=New-Item -Name "$nom" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\$nom","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp
  } 
  if ($service -eq "SAV"){ 
    Set-Location "C:\Users\Administrateur\Desktop\dossier\$service"
    $temp=New-Item -Name "$nom" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\$nom","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp
  } 

  if ($service -eq "INFORMATIQUE"){ 
    Set-Location "C:\Users\Administrateur\Desktop\dossier\$service"
    $temp=New-Item -Name "$nom" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\$nom","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp
  }
  if ($service -eq "DIRECTION"){ 
    Set-Location "C:\Users\Administrateur\Desktop\dossier\$service"
    $temp=New-Item -Name "$nom" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\$nom","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp
  }
  if ($service -eq "ADMINISTRATIF"){ 
    Set-Location "C:\Users\Administrateur\Desktop\dossier\$service"
    $temp=New-Item -Name "$nom" -ItemType directory
  $acl = Get-Acl $temp

  $permission = "ILARIA.LAN\$nom","FullControl","Allow"
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  $acl.SetAccessRule($accessRule)
  $acl | Set-Acl $temp
  }





  }

  }






  function DNS(){
  $DNSname = Read-Host -Prompt 'dns principale direct'
  $DNSnameindirect = Read-Host -Prompt 'dns principale indirect  209.17.85'



  #-------import des fonctionnalité server
  import-module servermanager

  #-------ajout du role dns
  Add-WindowsFeature DNS

  #-------ajout dns principal direct


  $DNSnamefichier=$DNSname+'.dns'
  dnscmd.exe localhost /ZoneAdd $DNSname /Primary /file $DNSnamefichier



  #-------creation des variable pour le dns indirect et PTR et hostname
  $DNSnameindirect=$DNSnameindirect+'.in-addr.arpa'
  $DNSnameindirectfichier=$DNSnameindirect+'.dns'
  $hostname=Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name
  $hostnameDNSdirect=$hostname+'.'+$DNSname
  $localIpAddress=((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
  $derniereOctet=$localIpAddress.Split(".")

  #-------ajout dns principal indirect

  dnscmd.exe localhost /ZoneAdd $DNSnameindirect /Primary /file $DNSnameindirectfichier
  #-------ajout du PTR zone indirect
  dnscmd.exe localhost /RecordAdd $DNSnameindirect $derniereOctet[3] PTR $hostnameDNSdirect

  Read-Host -Prompt 'fin tapez une touche pour quitter'


   }
















  function hostnameSuffixe(){
  $hostname = Read-Host -Prompt 'hostname'
  $DNSsuffixe = Read-Host -Prompt 'suffix dns'


  #----ajout du hostname
  $sysInfo = Get-WmiObject -Class Win32_ComputerSystem
  $result = $sysInfo.Rename($hostname)
  #----ajout du suffix dns
  Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name Domain -Value $DNSsuffixe
   }

















  function AD(){
  Set-ExecutionPolicy Unrestricted
  import-module servermanager
      add-windowsfeature adds-domain-controller   
  dcpromo.exe /unattend:C:\Users\Administrateur\Desktop\dcpromo-answer.txt
  read-host "pressez un e touche pour continuer"


   }








  function ADConfig(){
  Import-module ActiveDirectory



  # OrganizationalUnit
    
  NEW-ADOrganizationalUnit "Groupe" 
   NEW-ADOrganizationalUnit "Ordinateur"
  NEW-ADOrganizationalUnit "Utilisateur"

  NEW-ADOrganizationalUnit -Name "ProduitA" -Path "OU=Ordinateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "ProduitB" -Path "OU=Ordinateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "SAV" -Path "OU=Ordinateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "Direction" -Path "OU=Ordinateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "Administratif" -Path "OU=Ordinateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "Informatique" -Path "OU=Ordinateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "Assistante" -Path "OU=Ordinateur,DC=ILARIA,DC=lan"




  NEW-ADOrganizationalUnit -Name "ProduitA" -Path "OU=Utilisateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "ProduitB" -Path "OU=Utilisateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "SAV" -Path "OU=Utilisateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "Direction" -Path "OU=Utilisateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "Administratif" -Path "OU=Utilisateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "Informatique" -Path "OU=Utilisateur,DC=ILARIA,DC=lan"
  NEW-ADOrganizationalUnit -Name "Assistante" -Path "OU=Utilisateur,DC=ILARIA,DC=lan"



  # Group
   
  New-ADGroup -Name "ProduitA" -SamAccountName "ProduitA" -GroupCategory Security -GroupScope Global -DisplayName "ProduitA" -Path "OU=Groupe,DC=ILARIA,DC=lan" -Description "Groupe ProduitA"
  New-ADGroup -Name "ProduitB" -SamAccountName "ProduitB" -GroupCategory Security -GroupScope Global -DisplayName "ProduitB" -Path "OU=Groupe,DC=ILARIA,DC=lan" -Description "Groupe ProduitB"
  New-ADGroup -Name "SAV" -SamAccountName "SAV" -GroupCategory Security -GroupScope Global -DisplayName "SAV" -Path "OU=Groupe,DC=ILARIA,DC=lan" -Description "SAV"
  New-ADGroup -Name "Direction" -SamAccountName "Direction" -GroupCategory Security -GroupScope Global -DisplayName "Direction" -Path "OU=Groupe,DC=ILARIA,DC=lan" -Description "Groupe de direction avec droit particulier"
  New-ADGroup -Name "Administratif" -SamAccountName "Administratif" -GroupCategory Security -GroupScope Global -DisplayName "Administratif" -Path "OU=Groupe,DC=ILARIA,DC=lan" -Description "Groupe Administratif"
  New-ADGroup -Name "Assistante" -SamAccountName "Assistante" -GroupCategory Security -GroupScope Global -DisplayName "Assistante" -Path "OU=Groupe,DC=ILARIA,DC=lan" -Description "Assistante"
  New-ADGroup -Name "Informatique" -SamAccountName "Informatique" -GroupCategory Security -GroupScope Global -DisplayName "Informatique" -Path "OU=Groupe,DC=ILARIA,DC=lan" -Description "Informatique"




   # user





  $users = Import-Csv -Path 'C:\Users\Administrateur\Desktop\T_UTILISATEUR.csv' -Delimiter ";"
  foreach ($user in $users) {
  $nom="$($user.NOM)"
  $service="$($user.SERVICE)"
  $prenom="$($user.PRENOM)"



  [byte[]]$hours = @(0,0,0,192,255,7,192,255,7,192,255,7,192,255,7,192,255,7,0,0,0)            




  if ($service -eq "PRODUIT A"){ 
  New-ADUser -AccountPassword (ConvertTo-SecureString "Respons11" -AsPlainText -Force) -ChangePasswordAtLogon $false -City France -company "ILARIA" -DisplayName $nom -Enabled $true -Name $nom -SamAccountName $nom -Title CFO -Path "OU=ProduitA,OU=Utilisateur,DC=ILARIA,DC=lan" -givenname $nom -surname $prenom -userprincipalname ($nom+$prenom + "@ILARIA.LAN") -department "PRODUIT A" -description "My created user"
  Get-ADUser -Identity $nom | Set-ADUser -Replace @{logonhours = $hours}
  Add-ADGroupMember -Identity "ProduitA" -Member $nom

  } 
  if ($service -eq "PRODUIT B"){ 
  New-ADUser -AccountPassword (ConvertTo-SecureString "Respons11" -AsPlainText -Force) -ChangePasswordAtLogon $false -City France -company "ILARIA" -DisplayName $nom -Enabled $true -Name $nom -SamAccountName $nom -Title CFO -Path "OU=ProduitB,OU=Utilisateur,DC=ILARIA,DC=lan" -givenname $nom -surname $prenom -userprincipalname ($nom+$prenom + "@ILARIA.LAN") -department "PRODUIT B" -description "My created user"
  Get-ADUser -Identity $nom | Set-ADUser -Replace @{logonhours = $hours} 
  Add-ADGroupMember -Identity "ProduitB" -Member $nom

  } 
  if ($service -eq "SAV"){ 
  New-ADUser -AccountPassword (ConvertTo-SecureString "Respons11" -AsPlainText -Force) -ChangePasswordAtLogon $false -City France -company "ILARIA" -DisplayName $nom -Enabled $true -Name $nom -SamAccountName $nom -Title CFO -Path "OU=SAV,OU=Utilisateur,DC=ILARIA,DC=lan" -givenname $nom -surname $prenom -userprincipalname ($nom+$prenom + "@ILARIA.LAN") -department "SAV" -description "My created user"

  Add-ADGroupMember -Identity "SAV" -Member $nom

  } 

  if ($service -eq "INFORMATIQUE"){ 
  New-ADUser -AccountPassword (ConvertTo-SecureString "Respons11" -AsPlainText -Force) -ChangePasswordAtLogon $false -City France -company "ILARIA" -DisplayName $nom -Enabled $true -Name $nom -SamAccountName $nom -Title CFO -Path "OU=Informatique,OU=Utilisateur,DC=ILARIA,DC=lan" -givenname $nom -surname $prenom -userprincipalname ($nom+$prenom + "@ILARIA.LAN") -department "INFORMATIQUE" -description "My created user"

  Add-ADGroupMember -Identity "Informatique" -Member $nom
  }
  if ($service -eq "DIRECTION"){ 
  New-ADUser -AccountPassword (ConvertTo-SecureString "Respons11" -AsPlainText -Force) -ChangePasswordAtLogon $false -City France -company "ILARIA" -DisplayName $nom -Enabled $true -Name $nom -SamAccountName $nom -Title CFO -Path "OU=Direction,OU=Utilisateur,DC=ILARIA,DC=lan" -givenname $nom -surname $prenom -userprincipalname ($nom+$prenom + "@ILARIA.LAN") -department "DIRECTION" -description "My created user"

  Add-ADGroupMember -Identity "Direction" -Member $nom
  }
  if ($service -eq "ADMINISTRATIF"){ 
  New-ADUser -AccountPassword (ConvertTo-SecureString "Respons11" -AsPlainText -Force) -ChangePasswordAtLogon $false -City France -company "ILARIA" -DisplayName $nom -Enabled $true -Name $nom -SamAccountName $nom -Title CFO -Path "OU=Administratif,OU=Utilisateur,DC=ILARIA,DC=lan" -givenname $nom -surname $prenom -userprincipalname ($nom+$prenom + "@ILARIA.LAN") -department "ADMINISTRATIF" -description "My created user"
  Get-ADUser -Identity $nom | Set-ADUser -Replace @{logonhours = $hours} 
  Add-ADGroupMember -Identity "Administratif" -Member $nom

  }
  }
   

   }


  function impressionServ(){
    ipmo ServerManager
    add-WindowsFeature Print-Server

  }

  function Sauvegarde(){
Import-Module servermanager
Add-WindowsFeature Backup-Features
  }




  Write-Host "[1]- Changer le hostname et suffixe"
  Write-Host "[2]- Installer le DNS"
  Write-Host "[3]- Installer l'AD "
  Write-Host "[4]  Configuration de l'AD"
  Write-Host "[5]  install role server impression"
  Write-Host "[6]  creation des dossiers de partage a copier sur le dossier de partage samba"
  Write-Host "[7]  installer rôle sauvegarde"
  $Serveur = Read-Host "Choisissez une maison : 1- 7" 

  Switch ($Serveur)
  {
     1 {hostnameSuffixe}
     2 {DNS}
     3 {AD}
     4 {ADConfig}
     5 {impressionServ}
     6 {DossierCreation}
     7 {Sauvegarde}
     default {}
  }

   

   


