
###### <font style="color:#00b3ff">Delete Linux packet </font> 

```
sudo apt-get purge --auto-remove packagename_abcde 
```

###### <font style="color:#00b3ff">Display all connections</font>

``` 
sudo netstat -laputenv
```


###### <font style="color:#00b3ff">Display all services</font>

``` 
service --status-all
```

###### <font style="color:#00b3ff">Encrypt with GPG</font>

``` 
gpg -c file
```

###### <font style="color:#00b3ff">List installed packets</font>

``` 
apt list --installed
```

###### <font style="color:#00b3ff">Locate a file</font>

``` 
locate file_abcde
```

###### <font style="color:#00b3ff">List Firewall rules</font>

``` 
sudo iptables -nvL
```

###### <font style="color:#00b3ff">Activate/Deactivate a Firewall rule</font>

``` 
iptables -t filter -A INPUT -p tcp --dport 22 -j ACCEPT
```

###### <font style="color:#00b3ff">Restart Firewall</font>

``` 
sudo /etc/init.d/firewall restart
```

###### <font style="color:#00b3ff">Deactivate Firewall egress traffic</font>

``` 
iptables -I OUTPUT -j ACCEPT
```

###### <font style="color:#00b3ff">Check if a package is installed</font>

``` 
dpkg -s packagename_abcde 
```

###### <font style="color:#00b3ff">List hard-disk memory</font>

``` 
df -h
```

###### <font style="color:#00b3ff">Insert a new iptables rule at line 5</font>

``` 
iptables -I INPUT 5 -p tcp -m state --state NEW -m tcp --dport 4000 -j ACCEPT
```

###### <font style="color:#00b3ff">Update the system for the locate cmd</font>

``` 
sudo updatedb
```

###### <font style="color:#00b3ff">Compare 2 files</font>

``` 
diff file1 file2
```

###### <font style="color:#00b3ff">Search packages to install</font>

``` 
apt search packagename
```

###### <font style="color:#00b3ff">Listen on port 80 with netcat</font>

``` 
nc -lvkp 80
```

###### <font style="color:#00b3ff">Run a command in background</font>

`Add & at the end`

###### <font style="color:#00b3ff">Kill all processes from a program (ssh)</font>

``` 
killall ssh
```

###### <font style="color:#00b3ff">Change default shell (here to fish shell)</font>

``` 
chsh -s /usr/bin/fish
```

###### <font style="color:#00b3ff">Add a route to host on another interface (here on the wifi)</font>

``` 
sudo route add -host 192.168.1.21 dev wlp3s0
```

###### <font style="color:#00b3ff">Recursively search for text in files</font>

``` 
grep -nRi text_abcde *
```

###### <font style="color:#00b3ff">To Not display the following text</font>

``` 
grep -iv text_abcde
```

###### <font style="color:#00b3ff">Python print in a bash command</font>

``` 
echo `python -c "print 'A'*10"`
```

###### <font style="color:#00b3ff">Display .gz file</font>

``` 
zcat file.txt.gz
```

###### <font style="color:#00b3ff">Get info on a command</font>

``` 
whereis cmd_abcde
```

###### <font style="color:#00b3ff">Search for file containing a string</font>

``` 
grep -rnw /path/ -e 'string'
```

###### <font style="color:#00b3ff">List sudoers users</font>

``` 
grep -Po '^sudo.+:\K.*$' /etc/group
```

###### <font style="color:#00b3ff">Rebase the origin of git repo (to push over ssh)</font>

``` 
git remote set-url origin git@github.com:User_abc/file.git
```

###### <font style="color:#00b3ff">Generate alphabet with line return</font>

``` 
echo {A..Z}$'\n'
```

###### <font style="color:#00b3ff">Add user in group</font>

``` 
sudo usermod -a -G [group] [user]
```

###### <font style="color:#00b3ff">Find all SUID binary</font>

``` 
find / -user root -perm -4000 -print 2>/dev/null
```

###### <font style="color:#00b3ff">Untar a tar file</font>

``` 
tar -xvzf file.tar.gz
```

###### <font style="color:#00b3ff">List jobs</font>

``` 
jobs -l
```

###### <font style="color:#00b3ff">Set a job to foreground  (here the job id is 1)</font>

``` 
fg %1
```

###### <font style="color:#00b3ff">Clear history of the current session and bash history</font>

``` 
cat /dev/null > ~/.bash_history && history -c && exit
```

###### <font style="color:#00b3ff">Remove a service from startup</font>

``` 
sudo systemctl disable [service]
```

###### <font style="color:#00b3ff">Select the discover ports with Nmap and concatenate it with the ip address</font>

``` 
cat scan | awk -F '/' '{print "192.168.x.x:"$1}' > target
```

###### <font style="color:#00b3ff">Check the pages of man available for a cmd (ls)</font>

``` 
whatis ls
```

###### <font style="color:#00b3ff">View the manual page number 2 (for ls)</font>

``` 
man 2 ls
```

###### <font style="color:#00b3ff">Delete a route from the kernel routing table</font>

``` 
sudo route del -net 0.0.0.0 gw 192.168.x.x netmask 0.0.0.0 dev eth0
```

###### <font style="color:#00b3ff">Print the maximum of number of threads</font>

``` 
cat /proc/sys/kernel/threads-max
```

###### <font style="color:#00b3ff">DNS zone transfert with host cmd</font>

``` 
host -t ns test_abdce.com
```
``` 
host -l test_abdce.com ns1.test_abdce.com
```

###### <font style="color:#00b3ff">Add "hey" at the end of the file</font>

``` 
mv myfile{,hey}
```


---
###### <font style="color:#00b3ff">List screen sessions</font>

``` 
screen -ls
```

###### <font style="color:#00b3ff">Detach a screen session</font>

`CRTL + A + D`

###### <font style="color:#00b3ff">Attach a screen session</font>

``` 
screen -r [111111]
```

###### <font style="color:#00b3ff">Kill a session </font>

``` 
screen -X -S [111122] quit
```

###### <font style="color:#00b3ff">Give a name to session</font>

``` 
screen -S myname
```

---

###### <font style="color:#00b3ff">Grep the exact pattern from a file</font>

``` 
grep -w "abcde" textfile
```

###### <font style="color:#00b3ff">DNS Zone transfer</font>

``` 
host -t axfr target.domain.name target-dns-server
```
``` 
dig axfr @target-dns-server target.domain.name
```

###### <font style="color:#00b3ff">Check connection status (count)</font>

``` 
netstat -tan | awk '{print $6}' | sort | uniq -c
```
``` 
ss -s
```

###### <font style="color:#00b3ff">List SUID binaries</font>

``` 
find / -perm -u=s -type f 2>/dev/null
```

###### <font style="color:#00b3ff">Create a list from the words on a web page</font>

``` 
cewl http://test.com > dict.txt
```

###### <font style="color:#00b3ff">AWS list s3 bucket</font>

``` 
s3 ls s3://mytest
```

###### <font style="color:#00b3ff">AWS s3 bucket copy file</font>

``` 
s3 cp s3://mytest/myfile /tmp/myfile
```

###### <font style="color:#00b3ff">Get ACL of a file</font>

``` 
getfacl myfile
```

###### <font style="color:#00b3ff">Mount a share</font>

``` 
mount -t nfs 192.x.x.x:/remote/path/ /tmp/folder/
```

###### <font style="color:#00b3ff">Display Metadata of a pdf </font>

``` 
pdfinfo file.pdf
```

###### <font style="color:#00b3ff">Grep line which contains a specific string</font>

``` 
grep -E 'hello|world|tester' abc.log
```

###### <font style="color:#00b3ff">Grep line which does not contain a specific string</font>

``` 
grep -v 'test' abc.log
```

###### <font style="color:#00b3ff">Find a file in all current and subfolders</font>

``` 
find . -name "foo*"
```

###### <font style="color:#00b3ff">Find a directory</font>

``` 
find / -type d -name 'myfolder'
```

###### <font style="color:#00b3ff">Decode zip encoded text</font>

``` 
echo -n "H4sIAMvOiV4A/wVAIQ0AAAjLwh4Gi3gFBAIuqf9xtimk6i8M0yWJIw0AAAA=" | base64 -d | gunzip -c
```

###### <font style="color:#00b3ff">Mount folder in Kali Guest VMWare (in case of an error)</font>

``` 
sudo mount -t fuse.vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other
```

###### <font style="color:#00b3ff">Find string in all files recursively</font>

``` 
grep -r "texthere" .
```

###### <font style="color:#00b3ff">Add string before each line in a file</font>

``` 
awk '{print "abdce" $1}' list-of-files.txt > new_file
```

###### <font style="color:#00b3ff">Mount shared folder on linux guest VMWare </font>

``` 
sudo vmhgfs-fuse .host:/ /mnt/hgfs/ -o allow_other -o uid=1000
```

###### <font style="color:#00b3ff">Restart docker (whenever the docker network doesn't work)</font>

``` 
service docker restart
```

###### <font style="color:#00b3ff">Use a different Java JDK for ysoserial</font>

``` 
JDK/jdk-13/bin/java -jar ysoserial-all.jar CommonsCollections4 'test' | base64 -w 0
```


###### <font style="color:#00b3ff">Enable logging on terminal</font>

``` 
script ~/.terminal-logs/$(date +%Y-%m-%d_%H:%M:%S:%N).log
```

