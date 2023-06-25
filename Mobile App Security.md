----
## Android

###### <font style="color:#00b3ff">Reverse Apk</font> 

```
d2j-dex2jar test.apk
-> use jd-gui to read the code
-> use IDA pro
-> unzip the .apk and check the folders and files
-> on Windows: use jdax-gui
-> (complete decompiling): ava -jar apktool_2.3.3.jar d <apk>
```

###### <font style="color:#00b3ff">JADX</font> 

```
-> https://github.com/skylot/jadx (download the zip release)
-> On Windows: 
jadx.bat myApp.apk
jdax-gui.bat
```

###### <font style="color:#00b3ff">Apktool</font> 

```
apktool d myapp.apk -o extractedFolder
```

###### <font style="color:#00b3ff">Extract APK</font> 

```
- https://www.alphr.com/extract-apk-android/
```

###### <font style="color:#00b3ff">Dynamical Analyses with BurpSuite</font> 

```
-> Use Burp to intercept the requests on Android
 		https://support.portswigger.net/customer/portal/articles/1841101-configuring-an-android-device-to-work-with-burp

-> Android: https://support.portswigger.net/customer/portal/articles/1841102-Mobile%20Set-up_Android%20Device%20-%20Installing%20CA%20Certificate.html
```

###### <font style="color:#00b3ff">Bypass SSL pinning</font> 

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


###### <font style="color:#00b3ff">Bypass Flutter/Non-HTTP apps</font> 

```
- https://github.com/Impact-I/reFlutter/
- https://github.com/summitt/Burp-Non-HTTP-Extension/wiki#basic-set-up-for-mobile-testing-testing-on-two-machines

Repackage and re-sign the apps:
- https://github.com/patrickfav/uber-apk-signer

Reverse with Hopper disassembler:
-> https://infosecwriteups.com/bypass-freerasps-mobile-security-measures-in-flutter-8a6d4f192e0d
```


###### <font style="color:#00b3ff">Using ADB</font> 

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

###### <font style="color:#00b3ff">Android Patching APK</font> 

```
-> https://github.com/badadaf/apkpatcher

-> Ensure that apktool is version 2.7.0

-> Manual repackaging:
	- https://fadeevab.com/frida-gadget-injection-on-android-no-root-2-methods/
```

###### <font style="color:#00b3ff">Android processor architecture</font> 

```
-> ARM
-> Intel
-> MIPS
```

###### <font style="color:#00b3ff">Android check the stack smashing protection</font> 

```
find . -name "*.so" -exec pwn checksec --file {} \;
```

###### <font style="color:#00b3ff">Android Logs reading</font> 

```
-> use: adb logcat

adb logcat --pid=$(adb shell pidof -s com.xxxxx.yyyyy)
adb logcat --pid=12345
```

###### <font style="color:#00b3ff">Android sensitive locations</font> 

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

###### <font style="color:#00b3ff">Android debug test</font> 

```
- get the PID of the app:
	-> frida-ps -Uai

- Forward the app debug output to the debugger:
	-> adb forward tcp:1337 jdwp:<PID>

- Connect to the debugger:
	-> (echo suspend && cat) | jdb -attach localhost:1337
```

###### <font style="color:#00b3ff">Android Drozer framework</font> 

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

###### <font style="color:#00b3ff">Android Intent and Activities</font> 

```
- List all the activities (with objection):
	-> android hooking list activities

- Launch an activity:
	-> android intent launch_activity com.abc.abc.Views.Activities.LoginActivity
```

---
## iOS

###### <font style="color:#00b3ff">Reverse .ipa file</font> 

```
-> https://reverseengineering.stackexchange.com/questions/1594/possibilities-for-reverse-engineering-an-ipa-file-to-its-source	

-> locate the the bundle with objection:
	https://www.virtuesecurity.com/kb/ios-frida-objection-pentesting-cheat-sheet/

-> extract bundle folder: /private/var/containers/Bundle/Application/XXXX-XXXX-XXX-XXXXX-XXXXXX

-> copy the entire extracted folder (XXXX.app) in a "Payload" named folder and zip it YourChoiceName.ipa
	-> zip -r test.ipa Payload
```

###### <font style="color:#00b3ff">Dynamical Analyses with BurpSuite</font> 

```
-> iOS: https://portswigger.net/burp/documentation/desktop/mobile/config-ios-device

-> use Safari to download and install the cert from http://burp
```

###### <font style="color:#00b3ff">Bypass SSL pinning</font> 

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

###### <font style="color:#00b3ff">iOS Patching IPA (repackaging)</font> 

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

###### <font style="color:#00b3ff">Search for files on the Phone/iPad</font> 

```
-> get the files concerning the application: 

	grep -rnwi / -e "NameOfApp" > myfile
```

###### <font style="color:#00b3ff">iOS default ssh password</font> 

```
alpine
```

###### <font style="color:#00b3ff">iOS DCIM directory</font> 

```
/private/var/mobile/Media/DCIM/
```

###### <font style="color:#00b3ff">iOS Application path</font> 

```
/var/containers/Bundle/Application/
```

###### <font style="color:#00b3ff">iOS Logs reading</font> 

```
-> use itools on Windows
-> use oslog (install it from cydia on the device: http://cydia.saurik.com/package/net.limneos.oslog/)

	on MacOS
		idevice_id --list
		idevicesyslog -u <device_ID> 
```

###### <font style="color:#00b3ff">Jailbreak iOS 13</font> 

```
- install uncover ipa in iCloud
- delete old altstore, uncover from the phone
- on laptop install: altserver, iCloud (not from Microsoft Store), iTunes
- when launching altstore input the good location folder, open iCloud, iTunes at the same time (create an Apple ID if needed)
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

-> Link: https://ios.cfw.guide/installing-odysseyra1n/
```

###### <font style="color:#00b3ff">Jailbreak iOS 14</font> 

```
- checkra1n: https://checkra.in/
```

###### <font style="color:#00b3ff">Jailbreak iOS 15-16</font> 

```
- palera1n: https://pangu8.com/jailbreak/palera1n/
```

###### <font style="color:#00b3ff">iOS App Transport Security (ATS)</font> 

```
-> check Info.plist for the key NSAppTransportSecurity  (If the NSAllowsArbitraryLoads key is set to YES/TRUE, it will disable all ATS restrictions for all network connections)
```

###### <font style="color:#00b3ff">iOS get screenshots (specific number)</font> 

```
scp root@192.168.x.x:/User/Media/DCIM/100APPLE/*{35..39}.PNG .
```


---
### Frameworks

###### <font style="color:#00b3ff">Frameworks installation</font> 

```
-> install frida-tools (https://www.frida.re/docs/installation/)

-> install frida server https://github.com/frida/frida/releases

-> iOS instrumentation: https://github.com/ChiChou/grapefruit
```

###### <font style="color:#00b3ff">Objection and Frida installation</font> 

```
pip install frida-tools
pip install objection
```

###### <font style="color:#00b3ff">Frida Framework</font> 

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


###### <font style="color:#00b3ff">MobSF Framework</font> 

```
-> git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF
-> ./setup.sh && ./run.sh
-> access page: http://localhost:8000
-> for dynamical analysis use genymotion

=> use the docker image in case of versions bugs
```

###### <font style="color:#00b3ff">Listening remotely with frida-server (on phone, IP of the phone)</font> 

```
frida-server -l 0.0.0.0:19999 &
```

###### <font style="color:#00b3ff">Using Frida tools to get the PID of the target app</font> 

```
-> frida-ps -ai -H 192.168.99.242:27043   (in case of remote frida server)
-> frida-ps -Uai      (in case of usb connected frida server)
```

###### <font style="color:#00b3ff">Connect to remote frida server with custom port (pid of app is 1983 here)</font> 

```
-> objection -N --host 192.168.99.242 --port 27043 -g 1983 explore

-> frida-ps -ai -H 192.168.99.242:19999   (in case of remote frida server)
-> frida-ps -Uai      (in case of usb connected frida server)
```

###### <font style="color:#00b3ff">Connect to remote frida server with custom port (pid of app is 1983 here)</font> 

```
-> objection -N --host 192.168.99.242 --port 19999 -g 1983 explore

/!\ in case of a timeout use the App Identifier (example: com.google.android.gm)

-> objection -N --host 192.168.99.242 --port 19999 -g com.google.android.gm explore
```

###### <font style="color:#00b3ff">Connect to local frida (phone connected via usb)</font> 

```
objection -g 1983 explore
```

###### <font style="color:#00b3ff">Import AES hook script with objection</font> 

```
import aes-hook.js
```

###### <font style="color:#00b3ff">Objection dumping memory</font> 

```
memory dump all dump.txt
string dump.txt > strings.txt 
```

###### <font style="color:#00b3ff">Objection runtime injection test</font> 

```
ios ui alert "injection test"
```

###### <font style="color:#00b3ff">Objection remove jailbreak detection on an app</font> 

```
objection -g “<package_name>” explore --startup-command 'ios jailbreak disable' 

objection -N --host 192.168.99.242 --port 19999 -g ID_of_app explore --startup-command 'ios jailbreak disable'
```

###### <font style="color:#00b3ff">Objection Inspect cache and DB</font> 

```
- iOS:
	-> cmd: env
	-> get path to db
	-> sqlite connect path_to_db
	In the database:
		-> .tables
		-> select * from table_name
```

###### <font style="color:#00b3ff">Objection Hooking methods</font> 

```
- Android:
		-> android hooking get current_activity
		-> android hooking watch class com.xxxx.android.activity.MainActivity

- iOS:
		-> ios hooking list classes --ignore-native
		-> ios hooking list class_methods <class_name>
		-> ios hooking generate simple <class_name>
```

###### <font style="color:#00b3ff">Frida script example for injection</font> 

```
Java.perform(function() {
			var getAuthData_Activity = Java.use('o.getAuthData');
			getAuthData_Activity.IconCompatParcelizer.overload('android.content.Context', 'int', 'java.lang.String').implementation = function(message){
			return "Test injection";
			};
		});
```

###### <font style="color:#00b3ff">Frida run script</font> 

```
frida -U myApp -l myscript.js --debug
```

###### <font style="color:#00b3ff">Frida trace application</font> 

```
frida-trace -U --decorate -i "recv*" -i "send*" myApplication
```

###### <font style="color:#00b3ff">Frida trace iOS</font> 

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

###### <font style="color:#00b3ff">Bypass root/jailbreak detection</font> 

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

###### <font style="color:#00b3ff">Dynamical Analysis</font> 

```
https://medium.com/@ansjdnakjdnajkd/dynamic-analysis-of-ios-apps-wo-jailbreak-1481ab3020d8
```

###### <font style="color:#00b3ff">Mobile App Analysis Platform</font> 

```
https://github.com/m0bilesecurity/RMS-Runtime-Mobile-Security
```

###### <font style="color:#00b3ff">Frida docs</font> 

```
https://learnfrida.info/java/
```

###### <font style="color:#00b3ff">Check availability of an app region-locked</font> 

```
https://fnd.io/
```

###### <font style="color:#00b3ff">Android Tapjacking PoC</font> 

```
https://github.com/geeksonsecurity/android-overlay-malware-example

https://apkpure.com/overlay-test/com.mebarin.overlaytest
```

###### <font style="color:#00b3ff">Manual</font> 

```
https://github.com/OWASP/owasp-mstg

Objection commands documentation:
	https://github.com/sensepost/objection/tree/master/objection/console/helpfiles
```

###### <font style="color:#00b3ff">Mitigations</font> 

```
- Sensitive data in memory: 

https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05d-Testing-Data-Storage.md#checking-memory-for-sensitive-data-mstg-storage-10
```

###### <font style="color:#00b3ff">iOS debug</font> 

```
https://felipejfc.medium.com/the-ultimate-guide-for-live-debugging-apps-on-jailbroken-ios-12-4c5b48adf2fb
```

###### <font style="color:#00b3ff">iOS testing</font> 

```
https://ios.pentestglobal.com/basics/installing-tools
```

###### <font style="color:#00b3ff">Android Keylogger</font> 

```
- loki keyboard:

https://github.com/IceWreck/LokiBoard-Android-Keylogger
```