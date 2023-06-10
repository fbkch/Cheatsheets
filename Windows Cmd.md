###### <font style="color:#00b3ff">Display all types of file with explanations</font> 

```
assoc 
```

###### <font style="color:#00b3ff">Shred deleted file to make them unrecovable</font> 

```
cipher
```

###### <font style="color:#00b3ff">List drivers</font> 

```
driverquery -v
```

###### <font style="color:#00b3ff">Get the ip address</font> 

```
ipconfig
```

###### <font style="color:#00b3ff">List open ports</font> 

```
netstat -an
```

###### <font style="color:#00b3ff">Ping with a kind of traceroute</font> 

```
pathping
```

###### <font style="color:#00b3ff">Equivalent of traceroute</font> 

```
tracert
```

###### <font style="color:#00b3ff">Information about energy consumption</font> 

```
powercfg /energy /lastwake
```

###### <font style="color:#00b3ff">Shutting down system</font> 

```
shutdown
```

###### <font style="color:#00b3ff">Info about the system</font> 

```
systeminfo
```

###### <font style="color:#00b3ff">System file checker (scan files)</font> 

```
sfc
```

###### <font style="color:#00b3ff">Get list of running tasks</font> 

```
tasklist
```

###### <font style="color:#00b3ff">Kill a process (111) </font> 

```
taskkill -pid 111
```

###### <font style="color:#00b3ff">Netstat with grep equivalent</font> 

```
netstat -ano | find "est"
```

###### <font style="color:#00b3ff">Get the name of executable associated with a process</font> 

```
tasklist | find "[process id]"
```

###### <font style="color:#00b3ff">Use a remote machine</font> 

```
net use
```

###### <font style="color:#00b3ff">Check C partition for errors and fixes bad sectors</font> 

```
chkdsk /f C
```

###### <font style="color:#00b3ff">Create schedule task</font> 

```
schtasks
```

###### <font style="color:#00b3ff">Define access controls for a file</font> 

```
cacls
```

###### <font style="color:#00b3ff">dir command with options</font> 

```
dir /a-d (just the files) /od (sorted by date) 
```

---

###  Windows System Info Commands

###### <font style="color:#00b3ff">Get OS version</font> 

```
ver
```

###### <font style="color:#00b3ff">Show services</font> 

```
sc query state=all
```

###### <font style="color:#00b3ff">Show processes and services</font> 

```
tasklist /svc
```

###### <font style="color:#00b3ff">Show all processes and DLLs</font> 

```
tasklist /m
```

###### <font style="color:#00b3ff">Remote process listing</font> 

```
tasklist /S <ip> /v
```

###### <font style="color:#00b3ff">Force process to terminate</font> 

```
taskkill /PID <pid> /F
```

###### <font style="color:#00b3ff">Remote system info</font> 

```
systeminfo /S <ip> /U domain\user /P pwd
```

###### <font style="color:#00b3ff">Query remote registry</font> 

```
reg query \\<ip>\<RegDomain>\<Key> /v <Value> 
```

###### <font style="color:#00b3ff">Search registry for passwords</font> 

```
req query HKLM /f password /t REG_SZ /s 
```

###### <font style="color:#00b3ff">List all drives (must be admin)</font> 

```
fsutil fsinfo drives
```

###### <font style="color:#00b3ff">Search for all PDFs</font> 

```
dir /a /s /b c:\*.pdf*
```

###### <font style="color:#00b3ff">Search for patches</font> 

```
dir /a /b c:\windows\kb*
```

###### <font style="color:#00b3ff">Search files for password</font> 

```
findstr /si password *.txt| *.xml| *.xls
```

###### <font style="color:#00b3ff">Directory listing for C:</font> 

```
tree /F /A c:\ > tree.txt
```

###### <font style="color:#00b3ff">Save security hive to file </font> 

```
reg save HKLM\Security security.hive
```

###### <font style="color:#00b3ff">Current user</font> 

```
echo %USERNAME%
```

---

### Windows Net/Domain Commands

###### <font style="color:#00b3ff">Hosts in current Domain </font> 

```
net view /domain
```

###### <font style="color:#00b3ff">Hosts in [MYDOMAIN]</font> 

```
net view /domain:[MYDOMAIN]
```

###### <font style="color:#00b3ff">All users in current domain </font> 

```
net user /domain
```

###### <font style="color:#00b3ff">Add user </font> 

```
net user <user> <pass> /add
```

###### <font style="color:#00b3ff">Add user to Administrators </font> 

```
net localgroup "Administrators"	<user> /add
```

###### <font style="color:#00b3ff">Domain password policy</font> 

```
net accounts /domain
```

###### <font style="color:#00b3ff">List local Administrators </font> 

```
net localgroup "Administrators"
```

###### <font style="color:#00b3ff">List domain groups</font> 

```
net group /domain
```

###### <font style="color:#00b3ff">List users in Domain Admins</font> 

```
net group "Domain Admins" /domain
```

###### <font style="color:#00b3ff">List DCs for current domain</font> 

```
net group "Domain Controllers" /domain
```

###### <font style="color:#00b3ff">Current SMB shares</font> 

```
net share
```

###### <font style="color:#00b3ff">Active SMB sessions</font> 

```
net session | find / "\\"
```

###### <font style="color:#00b3ff">Unlock domain user account</font> 

```
net user <user> /ACTIVE:yes /domain
```

###### <font style="color:#00b3ff">Change domain user password</font> 

```
net user <user> "<newpassword>" /domain
```

###### <font style="color:#00b3ff">Share a folder</font> 

```
net share <share> C:\share /GRANT:Everyone,FULL
```

---

### Windows Remote Commands

###### <font style="color:#00b3ff">Remote process listing</font> 

```
tasklist /S <ip> /v
```

###### <font style="color:#00b3ff">Remote systeminfo</font> 

```
systeminfo /S <ip> /U domain\user /P Pwd
```

###### <font style="color:#00b3ff">Shares of remote computer</font> 

```
net share \\<ip>
```

###### <font style="color:#00b3ff">Remote filesystem (IPC$)</font> 

```
net use \\<ip>
```

###### <font style="color:#00b3ff">Map drive, specified credentials</font> 

```
net use z: \\<ip>\share <password> /user:DOMAIN\<user>
```

###### <font style="color:#00b3ff">Add registry key remotely</font> 

```
reg add \\<ip>\<regkey>\<value>
```

###### <font style="color:#00b3ff">Create a remote service (space after start=)</font> 

```
sc \\<ip> create <service> binpath=C:\Windows\System32\x.exe start= auto
```

###### <font style="color:#00b3ff">Copy remote folder</font> 

```
xcopy /s \\<ip>\dir C:\local
```

###### <font style="color:#00b3ff">Remotely reboot machine</font> 

```
shutdown /m \\<ip> /r /t 0 /f
```

---
### Windows Network Commands

###### <font style="color:#00b3ff">IP configuration</font> 

```
ipconfig /all
```

###### <font style="color:#00b3ff">Local DNS cache</font> 

```
ipconfig /displaydns
```

###### <font style="color:#00b3ff">Check open connections</font> 

```
netstat -ano
```

###### <font style="color:#00b3ff">netstat loop</font> 

```
netstat -anop tcp 1
```

###### <font style="color:#00b3ff">Listening ports</font> 

```
netstat -an | findstr LISTENING
```

###### <font style="color:#00b3ff">Routing table</font> 

```
route print
```

###### <font style="color:#00b3ff">Known MACs (ARP table)</font> 

```
arp -a
```

###### <font style="color:#00b3ff">DNS zone transfer</font> 

```
nslookup, set type=any, ls -d domain > results.txt, exit
```

###### <font style="color:#00b3ff">Domain SRV lookup (_ldap, _kerberos, _sip)</font> 

```
nslookup -type=SRV _www._tcp.url.com
```

###### <font style="color:#00b3ff">TFTP file transfer</font> 

```
tftp -I <ip> GET <remotefile>
```

###### <font style="color:#00b3ff">Saved wireless profiles</font> 

```
netsh wlan show profiles
```

###### <font style="color:#00b3ff">Disable firewall (*old)</font> 

```
netsh firewall set opmode disable
```

###### <font style="color:#00b3ff">Export wifi plaintext pwd</font> 

```
netsh wlan export profile folder=. key=clear
```

###### <font style="color:#00b3ff">List interfaces IDs/MTUs</font> 

```
netsh interface ip show interfaces
```

###### <font style="color:#00b3ff">Set IP</font> 

```
netsh interface	ip set address local static <ip> <nmask> <gw> <ID>
```

###### <font style="color:#00b3ff">Set DNS server</font> 

```
netsh interface ip set dns local static <ip>
```

###### <font style="color:#00b3ff">Set interface to use DHCP</font> 

```
netsh interface ip set address local dhcp
```

---
### Windows Utility Commands

###### <font style="color:#00b3ff">Display file contents</font> 

```
type <file>
```

###### <font style="color:#00b3ff">Forcibly delete all files in path</font> 

```
del <path>\*.* /a /s /q /f
```

###### <font style="color:#00b3ff">Find "str"</font> 

```
find /I "str" <filename>
```

###### <font style="color:#00b3ff">Line count of cmd output</font> 

```
<command> | find /c /v ""
```

###### <font style="color:#00b3ff">Schedule script to run 	(ex: at 14:45 cmd /c)</font> 

```
at HH:MM <script_path> [args]
```

###### <font style="color:#00b3ff">Run file as user</font> 

```
runas /user:<user> "file [args]"
```

###### <font style="color:#00b3ff">Restart now	</font> 

```
restart /r /t 0
```

###### <font style="color:#00b3ff">Removes CR and ^Z	</font> 

```
tr -d '\15\32' < win.txt > unix.txt
```

###### <font style="color:#00b3ff">Native compression</font> 

```
makecab <file>
```

###### <font style="color:#00b3ff">Uninstall patch	</font> 

```
Wusa.exe /uninstall /kb:<###>
```

###### <font style="color:#00b3ff">CLI event viewer</font> 

```
cmd.exe "wevtutil qe Application /c:40 /f:text /rd:true"
```

###### <font style="color:#00b3ff">Local user manager</font> 

```
lusrmgr.msc
```

###### <font style="color:#00b3ff">Services control panel</font> 

```
services.msc
```

###### <font style="color:#00b3ff">Task manager</font> 

```
taskmgr.exe
```

###### <font style="color:#00b3ff">Security policy manager</font> 

```
secpool.msc
```

###### <font style="color:#00b3ff">Event viewer</font> 

```
eventvwr.msc
```

###### <font style="color:#00b3ff">Find a file (here all flags, from the C:\ directory to be at the root)</font> 

```
cd C:\ && find flag* /s
```

###### <font style="color:#00b3ff">List all schedule tasks</font> 

```
schtasks
```
```
schtasks /query /fo LIST /v
```

###### <font style="color:#00b3ff">Add a folder to the path</font> 

```
setx path "%path%;C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x64"
```

###### <font style="color:#00b3ff">Remove folder from path</font> 

```
set path=%path:C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x64=%
```

###### <font style="color:#00b3ff">Run As (equivalent of sudo)</font> 

```
runas /noprofile /user:Administrator cmd
```

###### <font style="color:#00b3ff">Dhcp renew</font> 

```
ipconfig /release
```
```
ipconfig /renew
```

---
### PowerShell

###### <font style="color:#00b3ff">Exec ipconfig and write in file, then open it</font> 

```
ipconfig | Out-File -FilePath C:\IPtxt.txt; c:\iptxt.txt
```

###### <font style="color:#00b3ff">Run admin powershell window</font> 

```
Start-Process Powershell -verb runas
```

###### <font style="color:#00b3ff">Update help</font> 

```
Update-Help
```

###### <font style="color:#00b3ff">Check execution policy</font> 

```
Get-ExecutionPolicy
```

###### <font style="color:#00b3ff">Allow execution policy to run scripts</font> 

```
Set-ExecutionPolicy RemoteSigned
```

###### <font style="color:#00b3ff">Create a profile</font> 

```
New-Item -path $profile -type file -force
```

###### <font style="color:#00b3ff">Check if a PowerShell profile exist</font> 

```
Test-Path $Profile
```

###### <font style="color:#00b3ff">Six common cmdlets verbs</font> 

`Get, Set, Enable, Disable, New, Remove`

###### <font style="color:#00b3ff">Cmdlet syntax</font> 

`Verb-Noun -Parameter <arg>`

