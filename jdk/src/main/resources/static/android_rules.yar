

rule AceCard_a: Overlay Trojan
{
	meta:
		description = "AceCard Trojan / Overlay-Attacks"
		source = "https://securelist.com/blog/research/73777/the-evolution-of-acecard/"
	strings:
		$command_1 = "#intercept_sms_start"
		$command_2 = "#intercept_sms_stop"
		$command_3 = "#listen_sms_start"
		$command_4 = "#listen_sms_stop"
		$command_5 = "#send_sms"
		$command_6 = "#ussd"
	condition:
		2 of ($command_*) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.filter(/.*DEVICE_ADMIN_ENABLED.*/)
}


rule koodous_a: official
{
	meta:
		description = "adad - network"
	condition:
		androguard.activity(/ir.adad/i) or
		androguard.url(/s\.adad\.ir/)
}


rule adecosystems_a
{
    condition:
 		cuckoo.network.http_request(/ads01\.adecosystems\.com/) or cuckoo.network.http_request(/ads02\.adecosystems\.com/) or cuckoo.network.http_request(/ads03\.adecosystems\.com/) or cuckoo.network.http_request(/ads04\.adecosystems\.com/)
}


rule Adflex_a
{
	meta:
		description = "AdFlex SDK evidences"
		sample = "cae88232c0f929bb67919b98da52ce4ada831adb761438732f45b88ddab26adf"
	strings:
		$1 = "AdFlexSDKService" wide ascii
		$2 = "AdFlexBootUpReceiver" wide ascii
		$3 = "adflex_tracker_source" wide ascii
		$4 = "vn/adflex/sdk/AdFlexSDK" wide ascii
	condition:
		all of them
}


rule Adload_PUA_a
{
	meta:
		description = "This rule detects the Adload potential Unwanted"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "aquery/temp"
		$b = "Ljava/security/Permission;"
		$c = "getActiveNetworkInfo"
		$d = "com.appquanta.wk.MainService.DOWNLOAD_PROGRESS"
		$e = "modifyThread"
		$f = "init_url"
	condition:
		all of them		
}


rule adware_a
{
	meta:
		sample = "28e2d0f5e6dca1b108bbdc82d8f80cfbf9acd1df2e89f7688a98806dc01a89ba"
		search = "package_name:com.blackbean.cnmeach"
	strings:
		$a = "CREATE TABLE IF NOT EXISTS loovee_molove_my_date_history"
		$b = "loovee_molove_my_dating_task_delete_bak"
	condition:
		all of them
}


rule adware_b
{
	meta:
		description = "This rule detects ad application, used to show all Yara rules potential"
		sample = "33c61bf9ec395953851594d4595d33e004414ec17044f66858610cdac79b6946"
		sample2 = "d33b7e67696d0f30f4e2c360ce76b56f2ca78f181c456004ed395aaffd7c7f24"
		sample3 = "39b993dc0866075b2d489e98552cbf4f57b810c432b75a9a5df7599901318f4f"
	strings:
		$a = "MobclickAgent"
		$b = "Landroid/graphics/NinePatch;"
		$c = "#FloatService.createFloat(=========)"
	condition:
		all of them
}
rule adware2_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "33c61bf9ec395953851594d4595d33e004414ec17044f66858610cdac79b6946"
		sample2 = "d33b7e67696d0f30f4e2c360ce76b56f2ca78f181c456004ed395aaffd7c7f24"
		sample3 = "39b993dc0866075b2d489e98552cbf4f57b810c432b75a9a5df7599901318f4f"
	strings:
		$a = "missing appkey"
		$b = "/download/.um"
		$c = "noiconads.jar"
	condition:
		all of them
}


rule adware_c: ads
{
	meta:
		description = "Adware"
		sample = "5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b"
	strings:
		$string_a = "banner_layout"
		$string_b = "activity_adpath_sms"
		$string_c = "adpath_title_one"
		$string_d = "7291-2ec9362bd699d0cd6f53a5ca6cd"
	condition:
		all of ($string_*)
}


rule adware_d:asd
{
	condition:
		androguard.certificate.sha1("ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A")
}


rule protank_url_a: adware
{
	meta:
		description = ""
		sample = ""
	condition:
		androguard.url(/pro-tank-t34\.ru/) 
}
rule protank_package_name_a: adware
{
	meta:
		description = ""
		sample = ""
	condition:
		androguard.app_name("PlayMob Market")
}


rule main_a
{
	meta:
		description = "Identify Agent Smith core app"
		sample_analysis = "https://www.hybrid-analysis.com/sample/a3e95b5774c3f4d0f742fbc61ec0b3536deba4388840a398a8ec9c3eb351a177"
	strings:
		$a1 = "adsdk.zip"
		$a2 = "boot.zip"
		$a3 = "patch.zip"
		$b1 = "com.infectionAds.AdsManagement"
		$b2 = "com.infectionAds.AdmobPulic"
		$b3 = "com.infectionapk.patchMain"
		$c1 = /assets\/fonts\/DIsplay[0-9]*\.jpg/  //Encrypted malware
	condition:
		2 of ($a*) and (any of ($b*) or any of ($c*))
}
rule dropper_a
{
	meta:
		description = "Identifies a few known dropper apps"
		sample_analysis = "https://www.hybrid-analysis.com/sample/850253669b80ea2bf3ab02b3035ee330a8b718d7690f3fc0bf5d11b29e71b6ca/5d262933038838e412e9d9d1"
	condition:
		androguard.certificate.sha1("895d1abd26aaf7da4e52d37fa37d4e4a08bd5ca2") and
		(androguard.package_name("com.cool.temple007") or
		androguard.package_name("com.cool.rabbit.temple"))
}
rule JaguarKillSwitch_a: dropper_variant
{
	meta:
		description = "Identify (currently) dormant variants of Agent Smith droppers containing the 'Jaguar Kill Switch'"
	strings:
		$a1 = /com[\.\/]jaguar/
		$a2 = "hippo-sdk"
		$b1 = /tt.androidcloud.net/
		$b2 = /sdk.ihippogame.com/
		$b3 = /sdk.soonistudio.com/
	condition:
		all of ($a*) and any of ($b*)
}


rule AdwareAL_a
{
	meta:
		description = "Android Adware"
		md5 = "057eb20bab154b67f0640bc48e3db59a"
	strings:
		$a_1 = "rebrand.ly" fullword
		$a_2 = "setAdUnitId" fullword
		$a_3 = "loadAd" fullword
		$a_4 = "AdActivity" fullword
	condition:
		all of ($a_*)
}


rule BeiTaPlugin_a
{
	strings:
		$a1 = "assets/beita.renc"
		$a2 = "assets/icon-icomoon-gemini.renc"
		$a3 = "assets/icon-icomoon-robin.renc"
		$b = "Yaxiang Robin High"   // Decryption key
	condition:
		any of them// and
}


rule adwareCh_a: ccm
{
	meta:
		description = "Test for chinease adware base on ccm"
		sample = "4ecfcf8ea0f4e3739fb95f7c41d05e065bfd6f6ba94ff3591abd2479b86eb8c7"
	strings:
		$S_18_12106 = { 12 14 71 10 ?? ?? 05 00 0c 01 71 10 ?? ?? 01 00 0c 02 71 10 ?? ?? 02 00 0a 00 38 00 26 00 6e 10 ?? ?? 01 00 0a 00 d8 00 00 fe 6e 10 ?? ?? 01 00 0a 03 d8 03 03 fe 71 53 ?? ?? 41 04 0c 00 6e 10 ?? ?? 01 00 6e 10 ?? ?? 00 00 0c 01 1a 03 ?? ?? 6e 20 ?? ?? 31 00 0c 01 6e 20 ?? ?? 41 00 6e 30 ?? ?? 01 02 11 00 07 10 28 fe }
		$S_18_6e32 = { 6e 10 ?? 00 02 00 0c 00 6e 20 ?? ?? 30 00 0c 00 71 10 ?? ?? 00 00 0c 01 6e 10 ?? ?? 00 00 11 01 }
		$S_18_d858 = { d8 00 03 00 e1 01 04 00 8d 11 4f 01 02 00 d8 00 03 01 e1 01 04 08 8d 11 4f 01 02 00 d8 00 03 02 e1 01 04 10 8d 11 4f 01 02 00 d8 00 03 03 e1 01 04 18 8d 11 4f 01 02 00 0e 00 }
		$S_18_1262 = { 12 11 1a 00 ?? ?? 6e 20 ?? 00 03 00 0c 00 1f 00 ?? 00 6e 10 ?? ?? 00 00 0c 00 38 00 10 00 6e 10 ?? ?? 00 00 0a 02 38 02 0a 00 6e 10 ?? ?? 00 00 0a 00 33 10 04 00 01 10 0f 00 12 00 28 fe }
		$S_18_d852 = { d8 00 05 00 48 00 04 00 d8 01 05 01 48 01 04 01 d8 02 05 02 48 02 04 02 d8 03 05 03 48 03 04 03 e0 01 01 08 b6 10 e0 01 02 10 b6 10 e0 01 03 18 b6 10 0f 00 }
		$S_18_1366 = { 13 00 0c 00 71 20 ?? ?? 01 00 0a 00 59 20 ?? 00 13 00 10 00 71 20 ?? ?? 01 00 0a 00 59 20 ?? 00 13 00 14 00 71 20 ?? ?? 01 00 0a 00 59 20 ?? 00 13 00 18 00 71 20 ?? ?? 01 00 0a 00 59 20 ?? 00 0e 00 }
	condition:
		all of them
}


rule adware_e: installer
{
	condition:
		androguard.package_name("installer.com.bithack.apparatus")
}


rule Adware_a: test
{
	meta:
		description = "Adware Detect"
		sample = "631a898d184e5720edd5f36e6911a5416aa5b4dbbbea78838df302cffb7d36a1"
		author = "xophidia"
	strings:
		$string_1 = "21-11734"
		$string_2 = "()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"
		$string_3 = "()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz"
		$string_4 = "www.meitu.com"
		$string_5 = "cookiemanager-"
	condition:
		3 of ($*)
}


rule koodous_b: official
{
	meta:
		description = "Adware showing full-screen ads even if infected app is closed"
		sample = "0e18c6a21c33ecb88b2d77f70ea53b5e23567c4b7894df0c00e70f262b46ff9c"
		ref_link = "http://news.drweb.com/show/?i=10115&c=38&lng=en&p=0"
	condition:
		androguard.receiver(/com\.nativemob\.client\.NativeEventReceiver/)
}


rule koodous_c: official
{
	meta:
		description = "Adware showing full-screen ads even if infected app is closed"
		sample = "0e18c6a21c33ecb88b2d77f70ea53b5e23567c4b7894df0c00e70f262b46ff9c"
		ref_link = "http://news.drweb.com/show/?i=10115&c=38&lng=en&p=0"
	strings:
		$a = "com/nativemob/client/" // Ad-network library
	condition:
		all of them
}


rule Agent_a: official
{
	meta:
		description = "This rule detects one Agent variant w/ Admin Access"
		sample = "52f0a9d60f9e6ead70fd152aa4a3a8865215dd685128581697ce3ae3db768105"
	strings:
		$a = {6E 2E 41 44 44 5F 44 45 56 49 43 45 5F 41 44 4D 49 4E}
		$b = {6F 6D 2E 61 6E 72 64 2E 73 79 73 73 65 72 76 69 63 65 73 2F 66 69 6C 65 73 2F 73 75}
	condition:
		$a and $b
}


rule AgentGen_a: test
{
        meta:
                description = "Artemis Detecti ANDROID/Hiddad.P.Gen "
                sample = "7cf36007b51a319b3d1de2041a57c48a957965c9fe87194a5a7ab3303b50ea74"
        strings:
                $string_1 = "mmAUtjAeH"
        condition:
                $string_1 and
                androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") or
                androguard.url("http://apk-market.net/l2/aacc2ffc4d3e18ef12f908921ad235be")
}


rule adware_f:aggressive {
	meta:
		description = "This rule detects an aggressive adware that shows in your screen applications to download"
		sample = "bd3629e451fb294b4573a6aad94ae6789e654d9ce8e8a5aae92095bf440a17cf"
		sample2 = "3d1524c836cf54a4391b2677adb5c287da180c6428e5d2f9f34bb80fb2fbd315"
    strings:
        $a = "assets/sys_channel.ngPK"
        $b = {6D 4B 6E E6 30 73 21 75 77 6F 55 36 21} //From assets/mend.png
    condition:
        all of them
}


rule AirPush_a
{
	meta:
        description = "Evidences of AirPush Adware SDK. v1.2 20160208"
	strings:
    	$1 = "AirpushAdActivity.java"
    	$2 = "&airpush_url="
		$3 = "getAirpushAppId"
		$4 = "Airpush SDK is disabled"
		$5 = "api.airpush.com/dialogad/adclick.php"
		$6 = "res/layout/airpush_notify.xml"
		$7 = "Airpush Ads require Android 2.3"
		$8 = "AirpushInlineBanner"
		$9 = "AirpushAdEntity"
   	condition:
    	1 of them
}


rule packers_a: ali
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$ali_1 = "libmobisecy.so"
		$ali_2 = "libmobisecy1.zip"
	condition:
		any of them
}


rule Android_AliPay_smsStealer_a
{
	meta:
		description = "Yara rule for detection of Fake AliPay Sms Stealer"
		sample = "f4794dd02d35d4ea95c51d23ba182675cc3528f42f4fa9f50e2d245c08ecf06b"
		source = "http://research.zscaler.com/2016/02/fake-security-app-for-alipay-customers.html"
		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "START_SERVICE"
		$str_2 = "extra_key_sms"
		$str_3 = "android.provider.Telephony.SMS_RECEIVED"
		$str_4 = "mPhoneNumber"
	condition:
		androguard.certificate.sha1("0CDFC700D0BDDC3EA50D71B54594BF3711D0F5B2") or
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 		
		all of ($str_*)
}


rule clicker_a: url
{
	meta:
		description = "This rule detects the clicker variant malwares by using visited URLs"
		sample = "aa19c5038d74cf537de35b39bfbf82a35e03e4ab0635a14fdf857aabbe134382"
	condition:
		androguard.url(/^https?:\/\/.*\/z\/z2\/?/) or 
		androguard.url(/^https?:\/\/.*\/z\/z5\/?/) or
		androguard.url(/^https?:\/\/.*\/g\/getasite\/?/) or
		androguard.url(/^https?:\/\/.*\/z\/orap\/?/) or
		androguard.url(/^https?:\/\/.*\/g\/gstie\/?/)
}


rule clicker_b: urls
{
	meta:
		description = "This rule detects the android clicker variat"
		sample = "b855bcb5dcec5614844e0a49da0aa1782d4614407740cb9d320961c16f9dd1e7"
	condition:
		androguard.url(/bestmobile\.mobi/) or 
		androguard.url(/oxti\.org/) or
		androguard.url(/oxti\.net/) or
		androguard.url(/oin\.systems/) or 
		androguard.url(/wallpapers535\.in/) or 
		androguard.url(/pop\.oin\.systems/)
}


rule packers_b
{
	meta:
		description = "androidarmor"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_b = "cc.notify-and-report.net"
		$strings_c = "FK_G+IL7~t-6"
	condition:
		$strings_b or $strings_c
}


rule Android_Bankosy_a
{
	meta:
		description = "This rule detects Android.Bankosy"
		sample = "ac256d630594fd4335a8351b6a476af86abef72c0342df4f47f4ae0f382543ba"
		source = "http://www.symantec.com/connect/blogs/androidbankosy-all-ears-voice-call-based-2fa"
	strings:
		$string_1 = "*21*"
		$string_2 = "#disable_forward_calls"
		$string_3 = "#lock"
		$string_4 = "#intercept_sms_start"
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) 
}


rule androidbankosy_sh_a
{
	meta: 
		description = "Yara detection for Android.BankOsy"
		samples = "e6c1621158d37d10899018db253bf7e51113d47d5188fc363c6b5c51a606be2f and ac256d630594fd4335a8351b6a476af86abef72c0342df4f47f4ae0f382543ba"
		source = "http://www.symantec.com/connect/blogs/androidbankosy-all-ears-voice-call-based-2fa"
		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "credit_cards"
		$str_2 = "yyy888222kkk"
		$str_3 = "BLOCKED_NUMBERS"
		$str_4 = "*21*"
	condition:
		androguard.certificate.sha1("CE84D46572CF77DC2BBA7C0FCCDE411D6056027B") or 
		androguard.certificate.sha1("CA048A9BB7FE1CD4F2B6C3E1C3C622D540989E36") or 
		$str_1 and $str_2 and $str_3 and $str_4
}


rule android_dropper_sh_a
{
	meta:
		description = "Yara rule for detection of Android dropper.c samples"
		sample = "cad5d7125a28f7b1ea6ff6d358c05d25cdb2fd5c21e3f6e0973ea7c5a47206a3"
		source = "https://goo.gl/VBalPr"
		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "s_s_dcqjwouifi"
		$str_2 = "${LIBS_DIR}"
		$str_3 = "${ODEX_DIR}"
		$str_4 = "DES/CBC/PKCS5Padding"
	condition:
		androguard.certificate.sha1("7D4A2A6087D6F935E9F80A8500C42DB912C270C6") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 
		all of ($str_*)
}


rule koodous_d: official
{
	meta:
		description = "This rule detects the Android/Iop Malware"
		sample = "04addfd91ce7c31ce7e328dc310bafe0d7cf5ffc633fe1c5f2bc8a63a5812b07"
	strings:
		$a = "android.intent.action.USER_PRESENT"
		$b = "aHR0cHM6Ly93d3cuYmFpZHUuY29tLw=="
		$c = "IHN0YXJ0IC0tdXNlciAwIA=="
		$d = "/httpTrack"
		$e = "http://noicon.117q.com"
		$f = "android.intent.action.TIME_TICK"
	condition:
		all of them
}


rule Lockscreen_a: malware
{
	meta:
		description = "https://www.symantec.com/security_response/writeup.jsp?docid=2015-032409-0743-99&tabid=2"
	condition:
		androguard.service(/lockphone.killserve/i) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		androguard.filter(/android.intent.action.BOOT_COMPLETED/)
}


rule PornSlocker_a
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/first-kotlin-developed-malicious-app-signs-users-premium-sms-services/"
	strings:
		$ = "52.76.80.41"
		$ = "adx.gmpmobi.com"
	condition:
		all of them
}


rule smsriskware_a
{
	meta:
		description = "Payments(sms), storing gps location into .db files and sending through http"
	strings:
		$a = "http://112.74.106.240:7878/port/SInit/"
		$b = "http://112.74.106.240:7878/port/Sbill/"
		$c = "http://wiipay.cxso.cn/xml/listA.txt"
	condition:
		all of them 
}
rule adware_g {
	meta: 
		description = "Sends SMS/MMS - Installs adware"
	strings:
		$a = "http://115.28.52.43:9000/tabscr/appclient/fetchList!down.do?imei="
		$b = "http://sy.ppcool.com.cn:8089/pachong-server"
		$c = "http://sy.ppcool.com.cn:8089/pachong-server/download.service?"
		$d = "http://121.199.29.243/MobileInfoPlatform/ssi/encryption.action?v=14&p="
		$e = "http://121.199.29.243/MobileInfoPlatform/ssi/saveUser.action?v=14&p="
		$f = "http://211.151.131.83/mms/di/docheck.action"
		$g = "http://121.199.29.243/MobileInfoPlatform/ssi/applicationStatus.action?v=14&p="
	condition:
		any of them
		}
rule fakeAV_a
{
  meta:
  	description = "Redirects to fake AV page to install / send later sms / ads"
  strings:
  	$a = "http://www.antivirus-pro.us/downloads/list.txt"
  condition:
  	$a
}
rule smsSender_a
{
  meta:
  	description = "Has a list of countries and phones inside a .txt file. Apparently using some kind of code from BASICSMSSENDER"
  strings:
    $a = "SmsInfo() C-tor"
	$b = "dcSmsCount_"
	$c = "\n*****BINARY MESSAGE*****\n"
  condition:
    all of them 
}
rule fakeInstaller_a {
	meta:
		description = "Fake installer - Same signature always encrypted with RSA"
	strings:
		$a = "PKCS5Padding"
		$b = "Blowfish"
		$c ="ECB"
		$f= "http://qpclick.com/"
	condition:
		all of them 
}
rule riskWare_a {
	meta:
		description = "Riskware, installing thirdparty APKs and adware"
	condition:
		androguard.certificate.sha1("4D1C1D21519F3B03858627D624BE87DA961E83EC")
}
rule fakeInstallerSig_a {
	meta:
		description = "Fake installer - Same signature always encrypted with RSA"
	condition:
			androguard.certificate.sha1("17:42:6e:74:e2:96:d3:fa:31:01:04:62:08:d9:c7:84:1d:73:89:0c:de:de:80:a6:df:5e:ca:c6:43:1d:bc:37:57:c4:ad:e9:21:30:f4:0d:02:7d:f7:19:5a:54:ce:2a:6f:ee:85:02:32:50:23:74:7b:87:4d:ee:92:e1:63:24:b8:cc:16:50:62:0f:6e:f3:09:cd:75:2a:93:95:95:e6:4c:be:a4:73:27:4a:5b:5b:1c:f4:ef:02:cd:f8:6e:cc:30:5c:7e:f9:fe:54:96:f9:78:73:62:40:6e:10:ee:3d:9f:85:57:cf:59:25:09:06:c6:01:61:a1:3a:56:cf:7f:14:84:ed:4b:ff:6b:91:49:0a:ca:23:98:3c:84:c7:35:65:21:19:3e:2c:41:42:47:cd:74:84:4a:f3:fa:aa:b3:ed:ff:40:8b:ed:4c:a7:df:d1:9c:49:b1:38:49:bf:aa:20:e0:28:b9:04:07:44:d0:f4:e7:64:4b:29:a6:7a:ac:de:24:79:59:95:b2:fe:98:e6:61:08:dd:a8:9e:fc:59:51:49:f4:87:c4:0a:0b:e7:dc:09:73:86:a9:71:46:54:6c:11:11:bb:73:b8:5f:fa:c4:e0:03:85:0b:4c:19:f6:29:d3:1b:d8:c2:bc:da:c5:1b:6a:a0:6c:7b:89:5b:51")
}


rule Spywaller_a
{
	meta:
		description = "Android.Spywaller"
		sample = "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b"
		credits = "http://www.symantec.com/connect/blogs/spyware-androidspywaller-uses-legitimate-firewall-thwart-security-software"
		credits_2 = "http://www.symantec.com/security_response/writeup.jsp?docid=2015-121807-0203-99&tabid=2"
	strings:
		$a = "com.qihoo360.mobilesafe" //Malware looks for this app to remove it from device
		$b = "com.lbe.security"
		$c = "cn.opda.a.phonoalbumshou"
		$d = "safety_app"
	condition:
		all of them
		and androguard.permission(/android.permission.RESTART_PACKAGES/)
}


rule Android_Banker_Sberbank_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android Banker Sberbank"
		source = "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"
	condition:
		androguard.service(/MasterInterceptor/i) and 
		androguard.receiver(/MasterBoot/i) and 
		androguard.filter(/ACTION_POWER_DISCONNECTED/i)
}


rule android_ransom_wannacry_a
{
	meta:
		description = "This rule detects wannacry lockscreen display ransomware"
		sample = "ba03c39ba851c2cb3ac5851b5f029b9c"
		reference = "https://nakedsecurity.sophos.com/2017/06/09/android-ransomware-hides-in-fake-king-of-glory-game/"
	strings:
		$a_1 = "biaozhunshijian"
		$a_2 = "Lycorisradiata"
	condition:
		all of ($a_*)
}


rule Android_RuMMS_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detects Android.Banking.RuMMS"
		source = "https://www.fireeye.com/blog/threat-research/2016/04/rumms-android-malware.html"
	condition:
		(androguard.service(/\.Tb/) and 
		 androguard.service(/\.Ad/) and 
		 androguard.receiver(/\.Ac/) and 
		 androguard.receiver(/\.Ma/)) or
        (androguard.url(/http\:\/\/37\.1\.207/) and 
		 androguard.url(/\/api\/\?id\=7/))
}


rule android_spywaller_a
{
	meta:
		description = "Rule for detection of Android Spywaller samples"
		sample = "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b"
		source = "http://blog.fortinet.com/post/android-spywaller-firewall-style-antivirus-blocking"
	strings:
		$str_1 = "droid.png"
		$str_2 = "getSrvAddr"
		$str_3 = "getSrvPort"		
		$str_4 = "android.intent.action.START_GOOGLE_SERVICE"
	condition:
		androguard.certificate.sha1("165F84B05BD33DA1BA0A8E027CEF6026B7005978") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and 
		all of ($str_*)
}


rule Android_AndroRat_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-July-2016"
		description = "This rule will be able to tag all the AndroRat samples."
		source = "http://www.symantec.com/connect/nl/blogs/remote-access-tool-takes-aim-android-apk-binder"
	condition:
		androguard.service(/my.app.client/i) and
        androguard.receiver(/BootReceiver/i) and
		androguard.filter(/android.intent.action.BOOT_COMPLETED/i)
}


rule Trojan_Androrat_a
{
  meta:
      Author = "https://www.twitter.com/SadFud75"
  strings:
      $s_1 = "Hello World, AndroratActivity!" wide ascii
      $s_2 = "Lmy/app/client/AndroratActivity;" wide ascii
      $s_3 = "Androrat.Client.storage" wide ascii
  condition:
      any of them
}


rule AndroRAT_a
{
	meta:
		description = "AndroRAT"
	strings:
		$a = "Lmy/app/client/ProcessCommand" wide ascii
		$b = "AndroratActivity" wide ascii
		$c = "smsKeyWord" wide ascii
		$d = "numSMS" wide ascii
	condition:
		$a and ($b or $c or $d)
}


rule android_overlayer_a
{
	meta:
		description = "This rule detects the banker trojan with overlaying functionality"
		source =  "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"
		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "tel:"
		$str_2 = "lockNow" nocase
		$str_3 = "android.app.action.ADD_DEVICE_ADMIN"
		$str_4 = "Cmd_conf" nocase
		$str_5 = "Sms_conf" nocase
		$str_6 = "filter2" 
	condition:
		androguard.certificate.sha1("6994ED892E7F0019BCA74B5847C6D5113391D127") or 
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and 
		all of ($str_*))
}


rule anubisNew_July2019_a {
        meta:
                md5="3157e807e597bcd89f9af94e512583f6"
				blog="https://blog.trendmicro.com/trendlabs-security-intelligence/anubis-android-malware-returns-with-over-17000-samples/"
        strings:
                $a1 = "android.permission.WRITE_EXTERNAL_STORAGE"
                $a2 = "android.permission.READ_EXTERNAL_STORAGE"
                $b1 = "level_name"
                $b2 = "password"
                $b3 = "username"
                $b4 = "salary"
                $b5 = "name"
                $b6 = "id"
                $b7 = "employee"
                $c1 = "aHR0cDovL21hcmt1ZXpkbmJycy5vbmxpbmUvZGVuZW1lL2FwaTIucGhw"
                $c2 = "kdv.xml"
                $c3 = "aHR0cDovL3N1Y2Nlc3Npb25kYXIueHl6L2NvbnRpbnVpbmcvcmVzaWduZWQucGhw"
                $c4 = "config.xml"
        condition:
                all of ($a*) and
                all of ($b*) and
                2 of ($c*)
}


rule AnubisV1_a: rule0 {
	meta:
		author = "AnubisV1"
		date = "21 Aug 2018"
		url = "https://koodous.com/apks?search=tag:anubis%20AND%20date:%3E2018-07-30"
	condition:
		androguard.displayed_version("1.0") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.DREAMING_STOPPED") and 
		androguard.filter("android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE") and 
		androguard.filter("android.intent.action.PACKAGE_ADDED") and 
		androguard.filter("android.intent.action.PACKAGE_REMOVED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.intent.action.SCREEN_ON") and 
		androguard.filter("android.intent.action.SEND") and 
		androguard.filter("android.intent.action.SENDTO") and 
		androguard.filter("android.intent.action.USER_PRESENT") and 
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and 
		androguard.filter("android.net.wifi.WIFI_STATE_CHANGED") and 
		androguard.filter("android.provider.Telephony.SMS_DELIVER") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.filter("android.provider.Telephony.WAP_PUSH_DELIVER") and 
		androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON") and 
		androguard.functionality.socket.code(/invoke\-static\ v1\,\ v2\,\ v3\,\ v4\,\ v5\,\ Landroid\/view\/Gravity\;\-\>accept\(I\ I\ I\ Landroid\/graphics\/Rect\;\ Landroid\/graphics\/Rect\;\)V/) and 
		androguard.functionality.socket.code(/invoke\-static\/range\ v0\ \.\.\.\ v5\,\ Landroid\/view\/Gravity\;\-\>accept\(I\ I\ I\ Landroid\/graphics\/Rect\;\ Landroid\/graphics\/Rect\;\ I\)V/) and 
		androguard.number_of_filters == 17 and 
		androguard.number_of_receivers == 4 and 
		androguard.permission("android.permission.ACCESS_FINE_LOCATION") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.CALL_PHONE") and 
		androguard.permission("android.permission.GET_TASKS") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.PACKAGE_USAGE_STATS") and 
		androguard.permission("android.permission.READ_CONTACTS") and 
		androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_SMS") and 
		androguard.permission("android.permission.RECORD_AUDIO") and 
		androguard.permission("android.permission.SEND_SMS") and 
		androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.WRITE_SMS")
}


rule apk_inside_a
{
	meta:
		description = "This rule detects an APK file inside META-INF folder, which is not checked by Android system during installation"
		inspiration = "http://blog.trustlook.com/2015/09/09/android-signature-verification-vulnerability-and-exploitation/"
	strings:
		$a = /META-INF\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/
	condition:
		$a
}


rule slempo_detectado_a
{
        meta:
                description = "Trojan-Banker.Slempo"
        strings:
                $a = "org/slempo/service" nocase
        condition:
                1 of them
}


rule appsix_a
{
    strings:
		$a1 = "cvc_visa" 
		$a2 = "controller.php"  
		$a3 = "mastercard" 
	condition:
        androguard.package_name(/app.six/) and 
		2 of ($a*)
}


rule android_asacub_a
{
	meta:
		description = "Yara detection for Asacub"
		sample = "bca3c9fa1b81e1c325b2e731369bfdacda3149ca332c7411aeda9ad9c0c6a30c"
	strings:
		$str_1 = "res/xml/da.xml"
		$str_2 = "resources.arscPK"
	condition:		
		androguard.package_name("com.system.tossl") and
		androguard.activity(/\.MAC/) and 
		androguard.receiver(/\.BootReciv/) and 
		androguard.service(/\.IMService/) or 
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		all of ($str_*)
}


rule koodous_e: official
{
	meta:
		description = "This rule detects apks fom ASSD developer"
		sample = "cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e"
	condition:
		androguard.certificate.sha1("ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A")
}


rule Android_Aulrin_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-August-2016"
		description = "This rule try to detect Aulrin. This"
	condition:
		androguard.receiver(/z.core.OnBootHandler/i) and
		androguard.receiver(/z.core.SMSReciever/i) and
		androguard.service(/z.core.RunService/i) and
		androguard.activity(/xamarin.media.MediaPickerActivity/i) and 
        androguard.permission(/android.permission.CHANGE_COMPONENT_ENABLED_STATE/i)
}


rule Android_AVITOMMS_Variant_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "28-May-2016"
		description = "This rule try to detects Spy.Banker AVITO-MMS Variant"
		source = "https://blog.avast.com/android-banker-trojan-preys-on-credit-card-information"
	condition:
		(androguard.receiver(/AlarmReceiverKnock/) and 
		 androguard.receiver(/BootReciv/) and 
		 androguard.receiver(/AlarmReceiverAdm/))
}
rule Android_AVITOMMS_Rule2_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects Spy.Banker AVITO-MMS Variant"
		source = "https://blog.avast.com/android-banker-trojan-preys-on-credit-card-information"
	condition:
		androguard.service(/IMService/) and 
		androguard.receiver(/BootReciv/) and 
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i) and 
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/i) and 
		androguard.permission(/android.permission.SEND_SMS/i) and
		androguard.permission(/android.permission.INTERNET/i)
}


rule backdoor_a
{
	meta:
		description = "This rule detects samples with a backdoor"
		sample = "0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539"
	condition:
		androguard.url("http://sys.wksnkys7.com") 
		or androguard.url("http://sys.hdyfhpoi.com") 
		or androguard.url("http://sys.syllyq1n.com") 
		or androguard.url("http://sys.aedxdrcb.com")
		or androguard.url("http://sys.aedxdrcb.com")
}


rule Leecher_A_a
{
    condition:
        androguard.certificate.sha1("B24C060D41260C0C563FEAC28E6CA1874A14B192")
}


rule koodous_f: official
{
	meta:
		description = "Detects samples repackaged by backdoor-apk shell script"
		Reference = "https://github.com/dana-at-cp/backdoor-apk"
	strings:
		$str_1 = "cnlybnq.qrk" // encrypted string "payload.dex"
	condition:
		$str_1 and 
		androguard.receiver(/\.AppBoot$/)		
}


rule koodous_g: official
{
	meta:
		description = "Badpac adware"
		sample = "41911f5e76b7c367d8d4ee33fe17e12a6fe90633300d30a990278fc74b0c9535"
	strings:
	$sig1 = {2F 41 70 70 41 63 74 69 76 69 74 79 3B 00} // /AppActivity;
	$sig2 = {2F 4C 6F 63 6B 54 61 73 6B 3B 00} // /LockTask;
	$sig3 = {0A 72 65 63 65 6E 74 61 70 70 73 00} // recentapps
	$sig4 = {0B 68 6F 6D 65 63 6F 6E 74 72 6F 6C 00} // homecontrol
	$sig5 = {0E 63 68 65 63 6B 54 69 6D 65 42 79 44 61 79 00} // checkTimeByDay
	$sig6 = {16 6C 69 76 65 50 6C 61 74 66 6F 72 6D 41 64 43 61 74 65 67 6F 72 79 00} // livePlatformAdCategory
	condition:
		androguard.permission(/GET_TASKS/) and
		androguard.permission(/SYSTEM_ALERT_WINDOW/) and
		((all of them) or
		(2 of them and androguard.certificate.sha1("C0ACB33AF5EC1F66835566F9273165CCF8F8FBA4"))
		)	
}


rule packers_c: baidu
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$baidu_1 = "libbaiduprotect.so"
		$baidu_2 = "baiduprotect.jar"
		$baidu_3= "libbaiduprotect_x86.so"
	condition:
		all of them
}


rule packers_d: bangcle
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$bangcle_1 = "libsecmain.so"
		$bangcle_2 = "libsecexe.so"
		$bangcle_3 = "bangcleplugin"
	condition:
		all of them
}


rule BankBot_a
{
	meta:
		sample = "82541c1afcc6fd444d0e8c07c09bd5ca5b13316913dbe80e8a7bd70e8d3ed264"
	strings:
		$ = "/inj/"
		$ = "activity_inj"
		$ = /tuk/
		$ = /cmdlin/
	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and
		3 of them
}
rule BankBot2_a
{
	strings:
		$a0 = "/private/set_data.php"
		$a1 = "/private/settings.php"
		$a2 = "/private/add_log.php"
		$b = "/private/tuk_tuk.php"
	condition:
		$b and 1 of ($a*)
}
rule BankBot3_a
{
	strings:
		$ = "chins.php"
		$ = "live.php"
		$ = "add.php"
	condition:
		all of them
}


rule Trojan_a: BankBot
{
	meta:
        description = "Trojan targeting Banks with Overlays"
		source = "https://securify.nl/blog/SFY20170401/banking_malware_in_google_play_targeting_many_new_apps.html"
	strings:
		$c2_1 = "/private/tuk_tuk.php" nocase
		$c2_2 = "/private/add_log.php" nocase
		$c2_3 = "/private/set_data.php" nocase
		$c2_4 = "activity_inj" nocase
	condition:
		2 of ($c2_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
		)
}
rule Trojan_2_a: BankBot
{
	meta:
		sample = "b314e54a1161deccb2f582aaf6356f2e66a2f983dd1c1ebf7a5c5d9f5a873dba"
	strings:
		$sms_1 = "Sms Is Deleted !" nocase
		$sms_2 = "SMS is NOT DELETED" nocase
		$c2_1 = "/set/log_add.php" nocase
		$c2_2 = "/set/receiver_data.php " nocase
		$c2_3 = "/set/set.php" nocase
		$c2_4 = "/set/tsp_tsp.php" nocase
		$cmd_1 = "/proc/%d/cmdline" nocase
		$cmd_2 = "/proc/%d/cgroup" nocase
	condition:
		1 of ($sms_*)
		and 2 of ($c2_*)
		and 1 of ($cmd_*)
		and	androguard.permission(/android.permission.RECEIVE_SMS/)
}
rule Trojan_3_a: BankBot
{
	meta:
		sample = "ade518199cc4db80222403439ef6c7ee37cd57f820167cf59ee0fcdf5dcd2613"
	strings:
		$c2_1 = "settings.php" nocase
		$c2_2 = "set_data.php" nocase
		$c2_3 = "add_log.php" nocase
		$c2_4 = "activity_inj" nocase
		$cmd_1 = "/proc/%d/cmdline" nocase
		$cmd_2 = "/proc/%d/cgroup" nocase
	condition:
		2 of ($c2_*)
		and 1 of ($cmd_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
		)
}
rule Trojan_4_a: BankBot
{
	meta:
		description = "Bankbot - Sample is obfuscated with Allatori // 2017-08-03"
		sample = "787531c2b1bd8051d74ace245e0153938936a0d43137e207e32f7bbc6eb38e1d"
	strings:
		$c_0 = "activity_go_adm"
		$c_1 = "activity_inj"
		$c_2 = "device_admin.xml"
	condition:
		all of ($c_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
		)
}


rule Trojan_BankBot_7878_a {
	strings:
		$a0 = "twitter.com"
		$a1 = ":7878"
		$b0 = "Security protection"
		$b1 = "admin"
		$b2 = "WebServiceRobot"
		$c0 = "b3betb4"
		$c1 = "drenpngepgod235v"
		$c2 = "fkmlcbvio4eboi45"
		$c3 = "odsvr4i35b3"
		$c4 = "ooifjceiu523v"
		$c5 = "powv34b439"
		$c10 = "botId"
		$c11 = "bot_id"
	    $d0 = "url_db5o45"
	    $d1 = "url_dbnu56un4"
	    $d2 = "url_debrm454"
	    $d3 = "url_dnednr8643fg"
	    $d4 = "url_dnjs456y3"
	condition:
		all of ($a*) 
		and 2 of ($b*) 
		and 2 of ($c*) 
		and 1 of ($d*) 
}


rule BankbotAlpha_a
{
	meta:
		description = "This rule detects BankBot alpha samples"
		sample = "019bf3ab14d5749470e8911a55cdc56ba84423d6e2b20d9c9e05853919fc1462"
		more_info = "https://blog.fortinet.com/2017/04/26/bankbot-the-prequel"
	strings:
		$b_1 = "cclen25sm.mcdir.ru"
		$b_2 = "firta.myjino.ru"
		$b_3 = "adminko.mcdir.ru"
		$b_4 = "atest.mcdir.ru"
		$b_5 = "cclen25sm.mcdir.ru"
		$b_6 = "probaand.mcdir.ru"
		$b_7 = "firta.myjino.ru"
		$b_8 = "ranito.myjino.ru"
		$b_9 = "servot.myjino.ru"
		$b_10 = "jekobtrast1t.ru"
		$b_11 = "kinoprofi.hhos.ru"
		$a = "private/add_log.php"
	condition:
		$a and 
		any of ($b_*)
}


rule BankBot_b
{
	strings:
	  $ = "cmdline"
	  $ = "receiver_data.php"
	  $ = "set.php"
	  $ = "tsp_tsp.php"
	condition:
		all of them
}
rule BankBot2_b
{
    strings:
		$a = /\/\/[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\//
		$a1 = /index.php.action=command/
		$b = /adobe update/ nocase
		$b1 = /whatsapp/ nocase
		$c = /Confirm credit card details/ nocase
    condition:
		all of ($a*) and 1 of ($b*) and $c
}
rule BankBot1_a
{
	strings:
	  $a = "22http://ffpanel.ru/client_ip.php?key="
	condition:
		$a
}


rule silent_banker_a: banker
{
    meta:
        description = "This is just an example"
        thread_level = 3
        in_the_wild = true
    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
    condition:
        $a or $b or $c
}


rule Banker_a
{
	meta:
		description = "Detects a Banker"
		sample = "e5df30b41b0c50594c2b77c1d5d6916a9ce925f792c563f692426c2d50aa2524"
		report = "https://blog.fortinet.com/2016/11/01/android-banking-malware-masquerades-as-flash-player-targeting-large-banks-and-popular-social-media-apps"
	strings:
		$a1 = "kill_on"
		$a2 = "intercept_down"
		$a3 = "send_sms"
		$a4 = "check_manager_status"
		$a5 = "browserappsupdate"
		$a6 = "YnJvd3NlcmFwcHN1cGRhdGU=" // browserappsupdate
		$a7 = "browserrestart"
		$a8 = "YnJvd3NlcnJlc3RhcnQ=" // browserrestart
		$a9 = "setMobileDataEnabled"
		$a10 = "adminPhone"
	condition:
		8 of ($a*)
}
rule Acecard_a
{
	meta:
		description = "Detects some acecard samples"
		sample = "0973da0f5cc7e4570659174612a650f3dbd93b3545f07bcc8b438af09dc257a9"
		report = "https://securelist.com/blog/research/73777/the-evolution-of-acecard/"
	strings:
		$a = "#control_number"
		$b = "client number"
		$c = "INTERCEPTING_INCOMING_ENABLED"
		$d = "#intercept_sms_start"
		$e = "#intercept_sms_stop"
		$f = "intercepted incoming sms"
	condition:
		all of them
}
rule Acecard2_a
{
	meta:
		description = "Detects some acecard samples"
		sample = "88c744e563f7637e5630cb9b01cad663033ce2861cf01100f6c4e6fbb3e56df9"
		report = "https://securelist.com/blog/research/73777/the-evolution-of-acecard/"
	strings:
		$a = "Internet password"
		$b = "Security no."
		$c = "Keep your Internet Banking and secret authorisation code (SMS) secret. Don't reveal these details to anyone, not even if they claim to be NAB."
		$d = "TYPE_INSTALLED_APPS"
		$e = "TYPE_INTERCEPTED_INCOMING_SMS"
		$f = "TYPE_LISTENED_INCOMING_SMS"
		$g = "TYPE_CONTROL_NUMBER_DATA"
	condition:
		all of them and
		androguard.permission(/android.permission.RECEIVE_SMS/)
}


rule Banker_b
{
	condition:
		androguard.certificate.issuer(/@attentiontrust\.[a-z]{2,3}/) and
		androguard.certificate.issuer(/Attention Trust/)
}


rule detection_a
{
    strings:
	  $ = "Added %1$s to %2$s balance"  nocase
	  $ = "money_was_add"  nocase
	  $ = "!!Touch to sign in to your account"  nocase
	  $ = "You will be automatically charged %1$s"  nocase
	  $ = "adm_win"  nocase
	  $ = "shhtdi"  nocase
	  $ = "chat_interface"  nocase
	  $ = "chat_receive"  nocase
	  $ = "chat_sent"  nocase
	  $ = "chat_row" nocase
	condition:
		all of them
}


rule Banker1_a {
	strings:
		$ = "MessageReceiver"
		$ = "AlarmReceiver"
		$ = "BootReceiver"
		$ = "AdminRightsReceiver"
		$ = "AdminService"
		$ = "FDService"
		$ = "USSDService"
		$ = "MainService"
	condition:
		all of them
}
rule Banker2_a {
	strings:
		$ = "85.93.5.228/index.php?action=command"
		$ = "email@fgdf.er"
		$ = "majskdd@ffsa.com"
		$ = "185.48.56.10"
	condition:
		1 of them
}
rule Zitmo_a
{
	meta:
		description = "Trojan-Banker.AndroidOS.Zitmo"
		sample = "c0dde72ea2a2db61ae56654c7c9a570a8052182ec6cc9697f3415a012b8e7c1f"
	condition:
		androguard.receiver("com.security.service.receiver.SmsReceiver") and
		androguard.receiver("com.security.service.receiver.RebootReceiver") and
		androguard.receiver("com.security.service.receiver.ActionReceiver")
}
rule Banker3_a
{
	strings:
	$ = "cosmetiq/fl/service" nocase
	condition:
	1 of them
}


rule Banker2_b {
	strings:
		$r1 = "SmsReceiver"
		$r2 = "BootReceiver"
		$r3 = "AdminReceiver"
		$r4 = "AlarmReceiver"
		$r5 = "ServiceDestroyReceiver"
		$r6 = "AdminRightsReceiver"
		$r7 = "MessageReceiver"
		$s1 = "USSDService"
		$s2 = "GPService"
		$s3 = "FDService"
		$s4 = "MainService"
		$as1 = "AdminService"
		$as2 = "AdminRightsService"
	condition:
	3 of ($r*) and all of ($s*) and 1 of ($as*)
}
rule Trojan_SMS_a:Banker {
	strings:
		$ = "Landroid/telephony/SmsManager"
		$ = "szClassname"
		$ = "szICCONSEND"
		$ = "szModuleSmsStatus"
		$ = "szModuleSmsStatusId"
		$ = "szName"
		$ = "szNomer"
		$ = "szNum"
		$ = "szOk"
		$ = "szTel"
		$ = "szText"
		$ = "szpkgname"
	condition:
		all of them
}


rule marcher_a: official
{
	meta:
		description = "This rule detects the banker Marcher"
		sample = "d491e8ac326394e7b2cbc45c6599a677b6601978af87bc39c6bb0c41ba24f24e"
	strings:
		$cromosome_a = "setUsesChronometer"
		$cromosome_b = "Card number"
		$cromosome_c = "USSDService"
		$cromosome_d = "getDirtyBounds"
		$cromosome_e = "account_number_edit"
	condition:
		all of ($cromosome_*)
}


rule banking_a
{
	meta:
		description = "This rule detects is to detect a type of banking malware"
		sample = "33b1a9e4a1591c1a39fdd5295874e365dbde9448098254a938525385498da070"
	strings:
		$a = "cmVudCYmJg=="
		$b = "dXNzZCYmJg=="
	condition:
		all of them
}
rule marcher2_a
{
	strings:
		$a = "HDNRQ2gOlm"
		$b = "lElvyohc9Y1X+nzVUEjW8W3SbUA"
	condition:
		all of them
}
rule marcher3_a
{
	meta:
		sample1 = "087710b944c09c3905a5a9c94337a75ad88706587c10c632b78fad52ec8dfcbe"
		sample2 = "fa7a9145b8fc32e3ac16fa4a4cf681b2fa5405fc154327f879eaf71dd42595c2"
	strings:
		$b = "certificado # 73828394"
		$c = "A compania TMN informa que o vosso sistema Android tem vulnerabilidade"
	condition:
		all of them
}


rule YaYa_a: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.5_summer18"
		date = "27 Sep 2018"
		url = "https://koodous.com/apks?search=c2f8d276c497c571ac55346528af93d2e86d04d6e02e91a30e4cf44f125ae7c0%20OR%20%20f28d365c2b75b96faffa28eee85afddae8a2c6f1490e8294fb67e79874a7ff5c%20OR%20%20d0e28ee49d7b7feb5f94dbd00e4f5a6e4f418b536229188ef86bf45008c34d9b%20OR%20%208eb215552d186fdc24b53e34028e41e9e680ae1b32915f4b5c1a853142cdae8a"
	condition:
		androguard.activity("com.google.android.gms.common.api.GoogleApiActivity") and 
		androguard.activity("gjfid.pziovmiq.eefff.Main2Activity") and 
		androguard.activity("gjfid.pziovmiq.eefff.Main32Activity") and 
		androguard.activity("gjfid.pziovmiq.eefff.Main33Activity") and 
		androguard.activity("gjfid.pziovmiq.eefff.Main3Activity2") and 
		androguard.activity("gjfid.pziovmiq.eefff.MainActivity") and 
		androguard.activity("gjfid.pziovmiq.eefff.Num") and 
		androguard.activity("gjfid.pziovmiq.eefff.Scrynlock") and 
		androguard.activity("gjfid.pziovmiq.eefff.SmsActivity") and 
		androguard.app_name("Google Play Services.") and 
		androguard.displayed_version("1.0") and 
		androguard.filter("android.app.action.ACTION_DEVICE_ADMIN_DISABLE_REQUESTED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.intent.action.REBOOT") and 
		androguard.filter("android.intent.action.SEND") and 
		androguard.filter("android.intent.action.SENDTO") and 
		androguard.filter("android.provider.Telephony.SMS_DELIVER") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.filter("android.provider.Telephony.WAP_PUSH_DELIVER") and 
		androguard.filter("com.android.vending.INSTALL_REFERRER") and 
		androguard.filter("com.google.android.c2dm.intent.RECEIVE") and 
		androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON") and 
		androguard.functionality.crypto.class(/Lcom\/google\/android\/gms\/common\/util\/AndroidUtilsLight\;/) and 
		androguard.functionality.crypto.class(/Lcom\/google\/android\/gms\/common\/zzi\;/) and 
		androguard.functionality.crypto.class(/Lcom\/google\/firebase\/iid\/zzae\;/) and 
		androguard.functionality.crypto.code(/invoke\-virtual\ v1\,\ v0\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\[B\)\[B/) and 
		androguard.functionality.crypto.code(/invoke\-virtual\ v3\,\ v2\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\[B\)\[B/) and 
		androguard.functionality.crypto.method(/getErrorMessage/) and 
		androguard.functionality.crypto.method(/getPackageCertificateHashBytes/) and 
		androguard.functionality.crypto.method(/zza/) and 
		androguard.functionality.dynamic_broadcast.class(/Lcom\/google\/android\/gms\/common\/api\/internal\/GooglePlayServicesUpdatedReceiver\;/) and 
		androguard.functionality.dynamic_broadcast.class(/Lcom\/google\/android\/gms\/common\/util\/DeviceStateUtils\;/) and 
		androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 
		androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ v5\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 
		androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v2\,\ v3\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 
		androguard.functionality.dynamic_broadcast.method(/getDeviceState/) and 
		androguard.functionality.dynamic_broadcast.method(/getPowerPercentage/) and 
		androguard.functionality.dynamic_broadcast.method(/unregister/) and 
		androguard.functionality.imei.class(/Lgjfid\/pziovmiq\/eefff\/MyFirebaseInstanceIDService\;/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imei.method(/onTokenRefresh/) and 
		androguard.functionality.installed_app.class(/Lgjfid\/pziovmiq\/eefff\/MyFirebaseInstanceIDService\;/) and 
		androguard.functionality.installed_app.code(/invoke\-virtual\ v0\,\ v2\,\ Landroid\/content\/pm\/PackageManager\;\-\>getInstalledApplications\(I\)Ljava\/util\/List\;/) and 
		androguard.functionality.installed_app.method(/ALLATORIxDEMO/) and 
		androguard.functionality.run_binary.class(/Lgjfid\/pziovmiq\/eefff\/Scrynlock\;/) and 
		androguard.functionality.run_binary.code(/invoke\-static\ Ljava\/lang\/Runtime\;\-\>getRuntime\(\)Ljava\/lang\/Runtime\;/) and 
		androguard.functionality.run_binary.method(/onCreate/) and 
		androguard.functionality.sms.class(/Lgjfid\/pziovmiq\/eefff\/MyFirebaseMessagingService\;/) and 
		androguard.functionality.sms.class(/Lgjfid\/pziovmiq\/eefff\/SmsReceiver\;/) and 
		androguard.functionality.sms.class(/Lgjfid\/pziovmiq\/eefff\/StartBoot\;/) and 
		androguard.functionality.sms.code(/invoke\-virtual\/range\ v0\ \.\.\.\ v5\,\ Landroid\/telephony\/SmsManager\;\-\>sendTextMessage\(Ljava\/lang\/String\;\ Ljava\/lang\/String\;\ Ljava\/lang\/String\;\ Landroid\/app\/PendingIntent\;\ Landroid\/app\/PendingIntent\;\)V/) and 
		androguard.functionality.sms.method(/ALLATORIxDEMO/) and 
		androguard.functionality.socket.class(/Landroid\/support\/v4\/app\/NotificationManagerCompat\$SideChannelManager\;/) and 
		androguard.functionality.socket.class(/Landroid\/support\/v4\/media\/MediaBrowserCompat\$ServiceBinderWrapper\;/) and 
		androguard.functionality.socket.class(/Landroid\/support\/v4\/os\/ResultReceiver\;/) and 
		androguard.functionality.socket.code(/invoke\-interface\ v0\,\ v3\,\ v4\,\ Landroid\/support\/v4\/os\/IResultReceiver\;\-\>send\(I\ Landroid\/os\/Bundle\;\)V/) and 
		androguard.functionality.socket.code(/invoke\-interface\ v1\,\ v2\,\ Landroid\/support\/v4\/app\/NotificationManagerCompat\$Task\;\-\>send\(Landroid\/support\/v4\/app\/INotificationSideChannel\;\)V/) and 
		androguard.functionality.socket.code(/invoke\-virtual\ v1\,\ v0\,\ Landroid\/os\/Messenger\;\-\>send\(Landroid\/os\/Message\;\)V/) and 
		androguard.functionality.socket.method(/processListenerQueue/) and 
		androguard.functionality.socket.method(/send/) and 
		androguard.functionality.socket.method(/sendRequest/) and 
		androguard.functionality.ssl.class(/Landroid\/support\/v4\/text\/util\/LinkifyCompat\;/) and 
		androguard.functionality.ssl.class(/Landroid\/support\/v4\/util\/PatternsCompat\;/) and 
		androguard.functionality.ssl.code(/const\-string\ v1\,\ \"\(\(\(\?\:\(\?i\:http\|https\|rtsp\)\:\/\/\(\?\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,64\}\(\?\:\\\\\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,25\}\)\?\\\\\@\)\?\)\?\(\?\:\"/) and 
		androguard.functionality.ssl.code(/const\-string\ v1\,\ \"\(\(\?\:\\\\b\|\$\|\^\)\(\?\:\(\?\:\(\?i\:http\|https\|rtsp\)\:\/\/\(\?\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,64\}\(\?\:\\\\\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,25\}\)\?\\\\\@\)\?\)\(\?\:\"/) and 
		androguard.functionality.ssl.code(/const\-string\ v1\,\ \'https\:\/\/\'/) and 
		androguard.functionality.ssl.method(/\<clinit\>/) and 
		androguard.functionality.ssl.method(/addLinks/) and 
		androguard.number_of_filters == 15 and 
		androguard.number_of_permissions == 24 and 
		androguard.number_of_providers == 1 and 
		androguard.number_of_receivers == 7 and 
		androguard.number_of_services == 11 and 
		androguard.package_name("gjfid.pziovmiq.eefff") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.BIND_ACCESSIBILITY_SERVICE") and 
		androguard.permission("android.permission.CALL_PHONE") and 
		androguard.permission("android.permission.GET_TASKS") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.READ_EXTERNAL_STORAGED") and 
		androguard.permission("android.permission.READ_LOGS") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.RECEIVE_MMS") and 
		androguard.permission("android.permission.RECEIVE_SMS") and 
		androguard.permission("android.permission.REQUEST_DELETE_PACKAGES") and 
		androguard.permission("android.permission.SEND_SMS") and 
		androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and 
		androguard.permission("android.permission.VIBRATE") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.WRITE_SMS") and 
		androguard.permission("com.google.android.c2dm.permission.RECEIVE") and 
		androguard.permission("com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE") and 
		androguard.permission("gjfid.pziovmiq.eefff.permission.C2D_MESSAGE") and 
		androguard.provider("com.google.firebase.provider.FirebaseInitProvider") and 
		androguard.receiver("com.google.android.gms.measurement.AppMeasurementInstallReferrerReceiver") and 
		androguard.receiver("com.google.android.gms.measurement.AppMeasurementReceiver") and 
		androguard.receiver("com.google.firebase.iid.FirebaseInstanceIdReceiver") and 
		androguard.receiver("gjfid.pziovmiq.eefff.DAdm") and 
		androguard.receiver("gjfid.pziovmiq.eefff.MMSBroadcastReceiver") and 
		androguard.receiver("gjfid.pziovmiq.eefff.SmsReceiver") and 
		androguard.receiver("gjfid.pziovmiq.eefff.StartBoot") and 
		androguard.service("com.google.android.gms.measurement.AppMeasurementJobService") and 
		androguard.service("com.google.android.gms.measurement.AppMeasurementService") and 
		androguard.service("com.google.firebase.components.ComponentDiscoveryService") and 
		androguard.service("com.google.firebase.iid.FirebaseInstanceIdService") and 
		androguard.service("com.google.firebase.messaging.FirebaseMessagingService") and 
		androguard.service("gjfid.pziovmiq.eefff.Key") and 
		androguard.service("gjfid.pziovmiq.eefff.MyFirebaseInstanceIDService") and 
		androguard.service("gjfid.pziovmiq.eefff.MyFirebaseMessagingService") and 
		androguard.service("gjfid.pziovmiq.eefff.MyService") and 
		androguard.service("gjfid.pziovmiq.eefff.MyService33") and 
		androguard.service("gjfid.pziovmiq.eefff.SmsSendService1")
}






rule Banker_c:Gugi
{
	meta:
		description = "Ruleset to detect Gugi banker, more information @ https://medium.com/@entdark_/analyzing-an-android-banker-3849c9e4b6a9#.ckfr8afc8"
		sample = "afa13a98f31cdd4a847473d689747d6f1eec4151e0ae1c5db011bd931ba984ea"
	strings:
		$a = "tele2-rf.com:3000"
		$b = "create table settings(client_id integer,client_password TEXT,need_admin integer,need_card integer,first_bank integer,need_sber integer,need_tinkoff integer,need_vtb integer,need_alpha integer,need_raiff integer,server TEXT,filter TEXT,exist_bank_app integer);"
	condition:
		$a and $b
}


rule RuMMS_a {
	strings:
		$ = "5.45.78.20"
	condition:
		all of them
}


rule banker_Dew18_2_a
{
	meta:
		description = "Detects DewExample related samples"
		md5 = "510ed33e1e6488ae21a31827faad74e6"
	strings:
		$a_2 = "com.ktcs.whowho"
		$a_3 = "KEY_OUTGOING_REPLACE_NUMBER"
	condition:
		all of ($a_*)
}


rule fanta_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "commandObServer"
		$b = "ussd(): "
		$c = "const_id_send_sms"
		$d = "const_task_id_send_sms"
	condition:
		all of them
}


rule Android_Bankosy_nt_a
{
meta:
	description = "Try Android.Bankosy"
	sample = "ac256d630594fd4335a8351b6a476af86abef72c0342df4f47f4ae0f382543ba"
	source = "http://www.symantec.com/connect/blogs/androidbankosy-all-ears-voice-call-based-2fa"
strings:
	$string_1 = "#21#"
	$string_2 = "#disable_forward_calls"
	$string_3 = "#unlock"
	$string_4 = "#intercept_sms_stop"
condition:
	all of ($string_*) and
	androguard.permission(/android.permission.SEND_SMS/) 
}


rule basebridge_a
{
	meta:
		description = "A forwards confidential details to a remote server."
		sample = "7468c48d980f0255630d205728e435e299613038b53c3f3e2e4da264ceaddaf5"
		source = "https://www.f-secure.com/v-descs/trojan_android_basebridge.shtml"
	strings:
		$a = "zhangling1"
	condition:
		all of them
}


rule koodous_h: ClickFraud AdFraud SMS Downloader_Trojan
{
	meta:
		description = "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"
		sample = "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5"
	condition:
		androguard.activity(/com\.polaris\.BatteryIndicatorPro\.BatteryInfoActivity/i) and
		androguard.permission(/android\.permission\.SEND_SMS/)
}


rule bazdidyabScamCampaign_a
{
	meta:
		description = "A sample from Scam and Mass Advertisement campaign spreading their scamware over telegram, making money by scamming users and adding them to mass advertisement channels in Telegram"
		sample = "c3b550f707071664333ac498d1f00d754c29a8216c9593c2f51a8180602a5fab"
	condition:
		androguard.url(/^https?:\/\/([\w\d]+\.)?bazdidyabtelgram\.com\/?.*$/)
}


rule binka_a
{
	meta:
		description = "Binka banker trojan"
		sample = "4b2955436dacdc9427635794ff60465bc9bd69d31629e3337e012bd32e964e57"
	strings:
		$a = "EditText01"
		$b = "vel (exemplo: 960000111 e criar a palavra chave)"
		$c = "userText"
		$d = "LinearLayout04"
		$e = "TextView01"
		$f = "a de TMN tem de introduzir o n"
		$g = "LinearLayout03"
		$h = "LinearLayout02"
		$i = "LinearLayout01"
		$j = "LayoutOk"
		$k = "Para gerar o certificado de segura"
		$l = "startForService"
		$m = "Context is null"
	condition:
		all of them
}


rule WireX_a
{
	strings:
		$ = "g.axclick.store"
		$ = "ybosrcqo.us"
		$ = "u.axclick.store"
    	$ = "p.axclick.store"
	condition:
		1 of them
}


rule Btest_a
{
	meta:
		description = "btest"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_a = "aschannel" fullword
		$strings_b = "activesend" fullword
		$strings_c = "b_zq_lemon001" fullword
	condition:
		$strings_a or $strings_b or $strings_b or $strings_c
}


rule koodous_i: official
{
	meta:
		description = "This rule detects the cafebazaar app or link"
	condition:
		androguard.url(/cafebazaar\.ir/)
}


rule koodous_j: official
{
	meta:
		description = "Refering to background site so captchas get solved"
	strings:
		$a = "http://antigate.com/in.php"
		$b = "http://antigate.com/"
	condition:
		$a or 
		$b
}


rule certificates_a
{
	meta:
		description = "Identifies apps signed with certificates that are known to be from developers who make malicious apps"
	condition:
		androguard.certificate.sha1("2FC3665C8DAAE9A61CB7FA26FB3FEDE604DA4896") or
		androguard.certificate.sha1("3645AF60F8302526D376405C596596158379C7C2")
}


rule koodous_k: official
{
	meta:
		description = "Cheshmak Network"
	condition:
		androguard.package_name("me.cheshmak.android.sdk.core") or
		androguard.url(/sdk\.cheshmak\.me/) or
		androguard.url(/cheshmak\.me/) or
		androguard.url(/123\.cheshmak\.me/)
}


rule chineseporn_a: player
{
	meta:
		sample = "4a29091b7e342958d9df00c8a37d58dfab2edbc06b05e07dcc105750f0a46c0f"
	condition:
		androguard.package_name("com.mbsp.player") and
		androguard.certificate.issuer(/O=localhost/)
}


rule sensual_woman_a: chinese
{
	condition:
		androguard.package_name(/com.phone.gzlok.live/)
		or androguard.package_name(/com.yongrun.app.sxmn/)
		or androguard.package_name(/com.wnm.zycs/)
		or androguard.package_name(/com.charile.chen/i)
		or androguard.package_name(/com.sp.meise/i)
		or androguard.package_name(/com.legame.wfxk.wjyg/)
		or androguard.package_name(/com.video.uiA/i)
}
rule SMSSend_a
{
	strings:
		$a = "bd092gcj"
		$b = "6165b74d-2839-4dcd-879c-5e0204547d71"
		$c = "SELECT b.geofence_id"
		$d = "_ZN4UtilD0Ev"
	condition:
		all of them
}
rule SMSSend2_a
{
	strings:
		$a = "SHA1-Digest: zjwp/bYwUC5kfWetYlFwr/EuHac="
		$b = "style_16_4B4B4B"
		$c = "style_15_000000_BOLD"
	condition:
		all of them
}


rule chinese_porn_a: SMSSend
{
	condition:
		androguard.package_name("com.tzi.shy") or
		androguard.package_name("com.shenqi.video.nfkw.neim") or
		androguard.package_name("com.tos.plabe")
}


rule chineseporn4_a: SMSSend
{
	condition:
		androguard.activity(/com\.shenqi\.video\.Welcome/) or
		androguard.package_name("org.mygson.videoa.zw")
}


rule chineseporn5_a: SMSSend
{
	condition:
		androguard.package_name("com.shenqi.video.ycef.svcr") or 
		androguard.package_name("dxas.ixa.xvcekbxy") or
		androguard.package_name("com.video.ui") or 
		androguard.package_name("com.qq.navideo") or
		androguard.package_name("com.android.sxye.wwwl") or
		androguard.certificate.issuer(/llfovtfttfldddcffffhhh/)
}


rule chinese2_a: sms_sender
{
	condition:
		androguard.package_name(/com.adr.yykbplayer/) or 
		androguard.package_name(/sdej.hpcite.icep/) or
		androguard.package_name(/p.da.wdh/) or
		androguard.package_name(/com.shenqi.video.sjyj.gstx/) or
		androguard.package_name(/cjbbtwkj.xyduzi.fa/) or
		androguard.package_name(/kr.mlffstrvwb.mu/)
}


rule chinese_setting_a
{
	meta:
		sample = "ff53d69fd280a56920c02772ceb76ec6b0bd64b831e85a6c69e0a52d1a053fab"
	condition:
		androguard.package_name("com.anrd.sysservices") and
		androguard.certificate.issuer(/localhost/)
}


rule chineseSMSSender_a
{
	condition:
		androguard.package_name("com.android.phonemanager") and
		androguard.permission(/android.permission.SEND_SMS/)
}


rule ChinesePorn_a
{
	condition:
		androguard.url(/apk.iuiss.com/i) or
		androguard.url(/a0.n3117.com/i) or
		androguard.url(/http:\/\/www.sky.tv/) or
		cuckoo.network.dns_lookup(/apk.iuiss.com/i) or
		cuckoo.network.dns_lookup(/a0.n3117.com/i)
}
rule Shedun_a
{
	strings:
		$a = "hehe you never know what happened!!!!"
		$b = "madana!!!!!!!!!"
	condition:
 		all of them
}


rule ChinesePorn_2_a
{
	meta:
		description = "This rule detects dirtygirl samples"
		sample = "aeed925b03d24b85700336d4882aeacc"
	condition:
		androguard.receiver(/com\.sdky\.lyr\.zniu\.HuntReceive/) and
		androguard.service(/com\.sdky\.jzp\.srvi\.DrdSrvi/)
}


rule Chineseporn_3_a
{
	meta:
		description = "Detects few Chinese Porn apps"
	condition:
		(androguard.receiver(/lx\.Asver/) and
		 androguard.receiver(/lx\.Csver/))
}


rule ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5_a {
   meta:
      description = "chrysaor - file ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2018-09-21"
      hash1 = "ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5"
   strings:
      $s1 = "res/raw/cmdshellPK" fullword ascii
      $s2 = "res/raw/cmdshell" fullword ascii
      $s3 = "CHANGELOGPK" fullword ascii
      $s4 = "com.network.android" fullword wide
      $s5 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ja.propertiesPK" fullword ascii
      $s6 = "org/eclipse/paho/client/mqttv3/internal/nls/messages.propertiesPK" fullword ascii
      $s7 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ko.properties" fullword ascii
      $s8 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_cs.propertiesmTMO" fullword ascii
      $s9 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ru.properties" fullword ascii
      $s10 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_pt_BR.propertiesPK" fullword ascii
      $s11 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_zh_CN.properties" fullword ascii
      $s12 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_cs.propertiesPK" fullword ascii
      $s13 = "org/eclipse/paho/client/mqttv3/internal/nls/messages.properties]R" fullword ascii
      $s14 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_es.properties]S" fullword ascii
      $s15 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ko.propertiesPK" fullword ascii
      $s16 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_es.propertiesPK" fullword ascii
      $s17 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_pl.properties" fullword ascii
      $s18 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ja.properties" fullword ascii
      $s19 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_pt_BR.propertiesmS" fullword ascii
      $s20 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_pl.propertiesPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 800KB and
      8 of them
}


rule cloudsota_a
{
	meta:
		description = "http://www.cmcm.com/blog/en/security/2015-11-09/842.html"
		sample = "ff10aca93c95bb9c17e0fce10d819210907fcf84cfb061cdba4bd5ce47fd11d3"
	condition:
		androguard.certificate.sha1("FD2FF510E7896EB93840B6DFE8A109850F640CA9") or
		androguard.certificate.sha1("B03DB174D2643B2A7C23D6403169345D225DDB4F") or
		androguard.certificate.sha1("C3AA1AC48D59E56189BD1F1B09BD1C3FE2A33CB0")
}


rule comandroidmediacode_a
{
	meta:
		description = "This rule detects fraudulent applications based on Umeng"
		sample = "5df9766394428473b790a6664a90cfb02d4a1fd5df494cbedcb01e0d0c02090c"
	strings:
		$a = "ZN2in1cEP7_JNIEnvP8_jobject"
		$b = "PA8)\n"
	condition:
		$a and $b
		and androguard.app_name("com.android.mediacode")
}


rule koodous_l: official
{
	meta:
        description = "Rule to catch APKs with package name match with com.app.attacker."
    condition:
        androguard.package_name(/com\.app\.attacker\../)
}


rule com_house_crust_a
{
		strings:
			$a = "assets/com.jiahe.school.apk" nocase
		condition:
		androguard.package_name("com.house.crust") or
		androguard.certificate.sha1("E1DF7A92CE98DC2322C7090F792818F785441416") and
		$a
}


rule Android_Copy9_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "This rule try to detect commercial spyware from Copy9"
		source = "http://copy9.com/"
	condition:
		androguard.service(/com.ispyoo/i) and
        androguard.receiver(/com.ispyoo/i)
}


rule clicksummer_a
{
	meta:
		description = "domains used for copycat malware (CheckPoint)"
	strings:
		$ = ".clickmsummer.com"
		$ = ".mostatus.net"
		$ = ".mobisummer.com"
		$ = ".clickmsummer.com"
		$ = ".hummercenter.com"
		$ = ".tracksummer.com"
	condition:
 		1 of them
}


rule Coudw_a: official
{
	meta:
		description = "This rule detects one Coudw variant"
		sample = "240F3F5E1E6B4F656DCBF83C5E30BB11677D34FB10135ACC178C0F9E9C592C21"
	strings:
		$a = {2F73797374656D2F62696E2F62757379626F7820696E7374616C6C202D7220}
		$b = {436C6F756473536572766572312E61706B}
	condition:
		$a and $b
		or androguard.url(/s\.cloudsota\.com/)
}


rule crisis_a
{
	meta:
		description = "Crisis pack / Hacking team"
		sample = "29b1d89c630d5d44dc3c7842b9da7e29e3e91a644bce593bd6b83bdc9dbd3037"
	strings:
        $a = "background_Tr6871623"
	condition:
		$a and 
		androguard.permission(/android.permission.SEND_SMS/) and 
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALLS/) and
		androguard.permission(/android.permission.RECORD_AUDIO/)
}


rule curiosity_a
{
	meta:
		description = "Curiosity malware"
		sample = "481eef57626aceff65671e7985285f0f43def22b6007880af87d7fd1f4e12d64"
		source = "http://blog.avlsec.com/2016/10/3849/worm/"
	strings:
		$a = {4b 48 65 6c 6c 6f 20 49 20 66 6f 75 6e 64 20 79 6f 75 72 20 70 72 69 76 61 74 65 20 70 68 6f 74 6f 73 20 68 65 72 65}
		$b = {45 75 20 65 6e 63 6f 6e 74 72 65 69 20 73 75 61 73 20 66 6f 74 6f 73 20 70 72 69 76 61 64 61 73 20 61 71 75 69}
		$c = {53 42 6f 6e 6a 6f 75 72 20 6a 61 69 20 74 72 6f 75 76}
		$d = {6b 69 6e 67 73 74 61 72 62 6f 79 40 6f 75 74 6c 6f 6f 6b 2e 63 6f 6d}
		$e = {76 64 73 6f 66 74 2e 73 70 79 69 6e 67 2e 73 6a 69 6e 2e 70 65 72 6d 69 73 73 69 6f 6e 2e 43 32 44 5f 4d 45 53 53 41 47 45}
	condition:
		all of them
}


rule CyberPolice_ransomware_a
{
	meta:
		description = "CyberPolice Ransomware"
		sample = "0d369ed70cfe7fc809b7e963df22703d078bd881cd75404da8bf610423e9b12a"
	strings:
		$a = "iVBORw0KGgoAAAANSUhEUgAAAIAAAACABAMAAAAxEHz4AAAAGFBMVEVMaXGUwUWTwEaT"
		$b = "assets/anthology.apk"
		$c = "assets/assets/responded.bmp"
	condition:
		androguard.permission(/android.permission.ACCESS_COARSE_UPDATES/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.RESTART_PACKAGES/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.WRITE_SETTINGS/) and	
		androguard.permission(/android.permission.WRITE_CONTACTS/) and
		$a and ($b or $c)
}


rule Android_Dendroid_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detect Dendroid"
		source = "https://blog.lookout.com/blog/2014/03/06/dendroid/"
	condition:
		(androguard.service(/com.connect.RecordService/i) or
		androguard.activity(/com.connect.Dendroid/i)) and
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i)
}


rule Trojan_Dendroid_a
{
  meta:
      author = "https://www.twitter.com/SadFud75"
      description = "Detection of dendroid trojan"
  strings:
      $s1 = "/upload-pictures.php?"
      $s2 = "/get-functions.php?"
      $s3 = "/new-upload.php?"
      $s4 = "/message.php?"
      $s5 = "/get.php?"
  condition:
      3 of them
}


rule Dendroid_a
{
	meta:
        description = "Dendroid RAT"
	strings:
    	$s1 = "/upload-pictures.php?" wide ascii
    	$s2 = "Opened Dialog:" wide ascii
    	$s3 = "com/connect/MyService" wide ascii
    	$s4 = "android/os/Binder" wide ascii
    	$s5 = "android/app/Service" wide ascii
   	condition:
    	all of them
}
rule Dendroid_2_a
{
	meta:
        description = "Dendroid evidences via Droidian service"
	strings:
    	$a = "Droidian" wide ascii
    	$b = "DroidianService" wide ascii
   	condition:
    	all of them
}
rule Dendroid_3_a
{
	meta:
        description = "Dendroid evidences via ServiceReceiver"
	strings:
    	$1 = "ServiceReceiver" wide ascii
    	$2 = "Dendroid" wide ascii
   	condition:
    	all of them
}


rule Deng_a
{
	meta:
		description = "Android Deng, SMSreg variant related with cmgame.com chinese game portal and its SDK. #Deng #SMSreg #PUA #Riskware"
		sample = "7e053c38943af6a3e58265747bf65a003334b2a5e50ecc65805b93a583318e23"
	strings:
		$a = "cmgame/sdk/sms/" wide ascii
		$b = "cn.emagsoftware.gamehall.gamepad.aidl.AIDLService" wide ascii
		$c = "cn.emagsoftware.telephony.SMS_SENT" wide ascii
		$d = "sdklog.cmgame.com/behaviorLogging/eventLogging/accept?" wide ascii
		$e = "AndGame.Sdk.Lib_" wide ascii
	condition:
		(1 of them) or cuckoo.network.dns_lookup(/.*\.cmgame\.com/)
}


rule Regla_Deutsche_Finanz_Malware_a
{
meta:
    description = "Regla Yara para detectar malware del Deutsche Bank Finanz"
    sample = "83a360f7c6697eda7607941f769050779da1345a0dde015b049109bc43fc3a3e"
strings:
 	$a = "#intercept_sms_start"
	$b = "#intercept_sms_stop"
	$c = "org/slempo/service/DialogsStarter"
condition:
	$a and $b and $c
}


rule fraudulent_a:numeric_developers
{
	meta:
		koodous_search = "developer:91"
		koodous_search2 = "developer:86"
		koodous_search3 = "developer:34"
	condition:
		androguard.certificate.sha1("7D4EA444984A1AD84BBE408DB4A57A42B989E51A") or //developer 91
		androguard.certificate.sha1("78739E2E80F74715D31A72185942487216E40D81") or //developer 86
		androguard.certificate.sha1("E08260D36C0E5E2CEB9DE2FB0BAB0ABEA1471058") //developer 34
}


rule AoHaHa_a: SMSSender
{
	condition:
		androguard.certificate.sha1("79A25BCBF6FC9A452292105F0B72207C3381F288")
}


rule hao_a
{
	meta:
		description = "Developer / Company: hao"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		search = "cert:7428EA9322A6FBF2DDE4A6DB6C6E59237E0D8EC3" 
	condition:
		androguard.certificate.sha1("7428EA9322A6FBF2DDE4A6DB6C6E59237E0D8EC3")
}


rule Developers_with_known_malicious_apps_a
{
	meta:
		description = "This rule lists app from developers with a history of malicious apps"
		sample = "69b4b32e4636f1981841cbbe3b927560"
	strings:
		$a = "Londatiga"
		$b = "evaaee3ge3aqg"
		$c = "gc game"
		$d = "jagcomputersecuitity"
		$e = "aaron balder"
	condition:
		($a and androguard.certificate.sha1("ECE521E38C5E9CBEA53503EAEF1A6DDD204583FA")) or
		(androguard.certificate.sha1("1CA6B5C6D289C3CCA9F9CC0E0F616FBBE4E0573B")) or
		($b and androguard.certificate.sha1("79981C39859BFAC4CDF3998E7BE26148B8D94197")) or
		($c and androguard.certificate.sha1("CA763A4F5650A5B685EF07FF31587FA090F005DD")) or
		($d and androguard.certificate.sha1("4CC79D06E0FE6B0E35E5B4C0CB4F5A61EEE4E2B8")) or
		($e and androguard.certificate.sha1("69CE857378306A329D1DCC83A118BC1711ABA352")) 
}


rule dialer_a
{
	meta:
		description = "Android Dialers"
		sample = "6f29c708a24f1161d56ca36a5601909efac0087ffe4033ad87153e268ff52b06"
	strings:
		$a = {6C 6C 61 6D 61 64 61 5F 72 65 61 6C 69 7A 61 64 61}
	condition:
		$a and
		androguard.activity(/com\.phonegap\.proy/) and
		androguard.activity(/com\.keyes\.youtube/) and
		androguard.activity(/com\.phonegap\.plugins/) and 
		androguard.permission(/android\.permission\.CALL_PHONE/) 
}


rule DirtyGirl_a
{
	meta:
		description = "This rule detects dirtygirl samples"
		sample = "aeed925b03d24b85700336d4882aeacc"
	condition:
		androguard.service(/com\.door\.pay\.sdk\.sms\.SmsService/) or
		androguard.url(/120\.26\.106\.206/)
}


rule DOGlobal_a
{
	meta:
		description = "Evidences of DO global advertisement library / Adware "
	condition:
		cuckoo.network.dns_lookup(/do.global/) or cuckoo.network.dns_lookup(/do-global.com/) or cuckoo.network.dns_lookup(/ad.duapps.com/)
}


rule VideoTestNoicon_a
{
    meta:
        description = "Rule to catch APKs with app name VideoTestNoicon"
    condition:
        androguard.app_name(/VideoTestNoicon/i)
}


rule dowgin_a:adware
{
	meta:
		sample = "4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70"
		sample2 = "cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83"
		sample3 = "d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf"
		sample4 = "cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b"
	strings:
		$a = "http://112.74.111.42:8000"
		$b = "SHA1-Digest: oIx4iYWeTtKib4fBH7hcONeHuaE="
		$c = "ONLINEGAMEPROCEDURE_WHICH_WAP_ID"
		$d = "http://da.mmarket.com/mmsdk/mmsdk?func=mmsdk:posteventlog"
	condition:
		all of them
}


rule dowgin_b
{
	meta:
		sample = "13d63521e989be22b81f21bd090f325688fefe80e7660e57daf7ca43c31105cb"
		sample2 = "8840f0e97b7909c8fcc9c61cdf6049d08dc8153a58170976ff7087e25461d7bd"
		sample3 = "14f40c998a68d26a273eba54e1616a1a1cd77af4babb0f159a228754d3fd93ba"
		sample4 = "ad8803481b08f6d7bea92a70354eca504da73a25df3e52b0e028b1b125d9a6be"
		sample5 = "243c4042d8b0515cbb88887432511611fc5aa25e1d719d84e96fd44613a3e0cc"
	strings:
		$a = "SexPoseBoxLayout"
		$b = "PleasureStartsLayout"
		$c = "lYttxRF!2"
	condition:
		all of them
}


rule Downloader_a {
	condition:
		androguard.package_name("com.mopub") and
		androguard.filter("android.intent.action.ACTION_SHUTDOWN") and
		androguard.filter("android.net.wifi.supplicant.CONNECTION_CHANGE") and
		androguard.filter("android.intent.action.QUICKBOOT_POWEROFF") and
		androguard.filter("android.net.wifi.STATE_CHANGE") and
		androguard.filter("android.intent.action.BOOT_COMPLETED") and
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and
		androguard.filter("android.net.wifi.WIFI_STATE_CHANGED") and
		androguard.filter("android.intent.action.REBOOT")
}


rule downloader_a
{
	meta:
		description = "This rule detects applications that download another one"
		sample = "905db4c4fecac8a9d4b9d1cd16da97ea980aee58b88c78b0e636ff4144f24928"
	strings:
		$a = "Lcom/yr/sxmn4/ui/ai;" wide ascii
		$b = "Name: com/tencent/mm/sdk/platformtools/rep5402863540997075488.tmp"
		$c = "32102=\\u30af\\u30e9\\u30a4\\u30a2\\u30f3\\u30c8\\u306f\\u73fe\\u5728\\u5207\\u65ad\\u4e2d\\u3067\\u3059" wide ascii
	condition:
		all of them
}


rule Dresscode_a: official
{
	meta:
		description = "http://blog.checkpoint.com/2016/08/31/dresscode-android-malware-discovered-on-google-play/"
		sample = "3bb858e07a1efeceb12d3224d0b192fc6060edc8f5125858ca78cdeee7b7adb9"
	condition:
		androguard.url(/inappertising\.org/) or
		cuckoo.network.dns_lookup(/inappertising\.org/) 
}


rule droidap_a
{
	meta:
		description = "This rule detects DroidAp trojans"
		sample = "4da3d9ed1a02833496324263709bebe783723e1c14755c080449a28f6aa111dc"
		sample2 = "c4c9b79d288b0a38812b81e62d41a49e3b79fb8b04c58376c26c920547e23ac3"
		sample3 = "51f93aa72ca0364860e6bffccc1bef5171692275650d9e1988d37ce748ea0558"
		reference = "https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Andr~DroidAp-A/detailed-analysis.aspx"
	strings:
		$a = "_DroidPhoneStateListener.java"
		$b = "nameOfElement1"
		$c = "3 fjPjJj"
	condition:
		all of them
}
rule droidap2_a
{
	meta:
		description = "This rule detects DroidAp trojans"
		sample = "ad3cd118854e939ab6a9bb6e98b63740e353ab96116f980de0d76fa698e0577a"
		sample2 = "b9a9b500068fd8afaf341fd6290834c3437f62e04701922336644a26bfc7a6d8"
		sample3 = "f31116a7f8639d91288baa868222984e90556b2832a444f2ef3beccd8c6def3e"
		reference = "https://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/Andr~DroidAp-A/detailed-analysis.aspx"
	strings:
		$a = "KWM4oC=0_"
		$b = "Name: classes.dey"
		$c = "com.hbw.droidapp.FromAlarm"
	condition:
		all of them
}




rule droidcollector_a
{
	meta:
		description = "Detect stealer tool (Sending collected data to ext server"
	strings:
		$a = "http://85.10.199.40/ss/media1.php"
		$b = "http://85.10.199.40/ss/xml22.php"
	condition:
		androguard.url(/85\.10\.199\.40/) or $a or $b
}


rule Trojan_Droidjack_a
{
  meta:
      author = "https://twitter.com/SadFud75"
  condition:
      androguard.package_name("net.droidjack.server") or androguard.activity(/net.droidjack.server/i)
}


rule koodous_m: official
{
	meta:
		description = "This rule detects malicious apps with DroidJack components"
		sample = "51b1872a8e2257c660e4f5b46412cb38"
	condition:
		androguard.package_name("net.droidjack.server") and
		androguard.service(/net\.droidjack\.server\./)
}


rule droidjack_RAT_malware_a
{
	meta:
		description = "Droidjack RAT Malware - http://www.droidjack.net/"
	condition:
		androguard.package_name(/droidjack/i) and
		androguard.url(/droidjack\.net\/Access\/DJ6\.php/) and
		androguard.url(/droidjack\.net\/storeReport\.php/) and
		androguard.receiver("net.droidjack.server.Connector") and
		androguard.receiver("net.droidjack.server.CallListener") and
		androguard.service("net.droidjack.server.Controller") and
		androguard.service("net.droidjack.server.GPSLocation") and
		androguard.service("net.droidjack.server.Toaster") 
}


rule koodous_n: official
{
	meta:
		description = "This rule detects a string that appears in droidplugin/core/PluginProcessManager"
		sample_based_on = "49ff608d2bdcbc8127302256dc7b92b12ea9449eb96255f9ab4d1da1a0405a1b"
	strings:
		$message_str = "preMakeApplication FAIL"
	condition:
		$message_str
}


rule koodous_o: official
{
	meta:
		description = "Strings from droidplugin code"
		sample_based_on = "49ff608d2bdcbc8127302256dc7b92b12ea9449eb96255f9ab4d1da1a0405a1b"
	strings:
		$dbhook = "SQLiteDatabaseHook"
		$message_str = "preMakeApplication FAIL"
	condition:
		all of them
}


rule dropper_b {
	meta:
		sample = "42c5fd9d90b42b1e7914bf10318ba0e8d349b584b05471da78be49fc76e385a4"
		sample2 = "5e0cfae3b637a383032ec75adaf93be96af8414e9280f2e1e3382848feef2b72"
	strings:
		$a = "gDexFileName"
		$b = "lib/armeabi/libzimon.so"
		$c = "Register_PluginLoaderForCryptDexFile_Functions"
		$d = "javax/crypto/Cipher"
	condition:
		all of them
}


rule dropper_c
{
	meta:
		description = "This rule detects a dropper app"
		sample = "6c0216b7c2bffd25a4babb8ba9c502c161b3d02f3fd1a9f72ee806602dd9ba3b"
		sample2 = "0089123af02809d73f299b28869815d4d3a59f04a1cb7173e52165ff03a8456a"
	strings:
		$a = "Created-By: Android Gradle 2.0.0"
		$b = "UnKnown0"
		$c = "UnKnown1"
		$d = "Built-By: 2.0.0"
	condition:
		all of them
}


rule dropper_d
{
	meta:
		description = "Detects a dropper"
		samples = "4144f5cf8d8b3e228ad428a6e3bf6547132171609893df46f342d6716854f329, e1afcf6670d000f86b9aea4abcec7f38b7e6294b4d683c04f0b4f7083b6b311e"
	strings:
		$a = "splitPayLoadFromDex"
		$b = "readDexFileFromApk"
		$c = "payload_odex"
		$d = "payload_libs"
		$e = "/payload.apk"
		$f = "makeApplication"
	condition:
		all of them
}


rule SMSFraude_a
{
	meta:
		autor = "sadfud"
		description = "Se conecta a un panel desde el que descarga e instala nuevas aplicaciones"
	condition:
		androguard.url(/app\.yx93\.com/)		
}


rule dropper_e:realshell {
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
	condition:
		$b
}




rule Dvmap_a
{
	strings:
		$a = "com.colourblock.flood"
	condition:
		$a and not androguard.certificate.sha1("D75A495C4D7897534CC9910A034820ABD87D7F2F") 
}


rule edwin_a: malware
{
	meta:
		description = "edwin adware"
		sample = "6316b74bc4ee0457ed0b0bbe93b082c2081d59e0b8e0bf6022965b0c5a42ea94"
		url_report = "http://researchcenter.paloaltonetworks.com/2017/04/unit42-ewind-adware-applications-clothing/"
	condition:
		(androguard.activity(/b93478b8cdba429894e2a63b70766f91.ads/i) or
		androguard.activity(/delete.off/i)) and
		androguard.certificate.sha1("405E03DF2194D1BC0DDBFF8057F634B5C40CC2BD")
}


rule eicar_a
{
	meta:
		description = "EICAR-AV-Test"
		source = "http://www.eicar.org/86-0-Intended-use.html"
	strings:
		$eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii wide
	condition:
		$eicar
}


rule ExaSpySimple_a
{
	meta:
		description = "https://www.skycure.com/blog/exaspy-commodity-android-spyware-targeting-high-level-executives/"
		sample = "fee19f19638b0f66ba5cb32c229c4cb62e197cc10ce061666c543a7d0bdf784a"
	strings:
		$a = "andr0idservices.com" nocase
	condition:
		$a
}


rule Exploit_a
{
	meta:
		description = "Detects some exploits"
		sample = "168f82516742a9580fb9d0c907140428f9d3837c88e0b3865002fd221b8154a1"
	strings:
		$a = "Ohh, that's make joke!"
		$b = "CoolXMainActivity"
	condition:
		all of them
}


rule detection_b
{
	strings:
		$ = "mspace.com.vn"
		$ = "optimuscorp.pw"
		$ = "ads_manager/get_facebook_ads_manager.php" 
	condition:
		2 of them or
		androguard.url("mspace.com.vn") or
		androguard.url("optimuscorp.pw") or
		androguard.certificate.sha1("A7E0323BFEFED2929F62EFC015ED465409479F6F") or
		androguard.certificate.issuer(/assdf/)
}


rule HillClimbRacing_a
{
	meta:
		description = "This rule detects fake application of Hill Climb Racing"
		sample = "e0f78acfc9fef52b2fc11a2942290403ceca3b505a8e515defda8fbf68ac3b13"
	condition:
		androguard.package_name("com.fingersoft.hillclimb") and
		not androguard.certificate.sha1("9AA52CC5C1EA649B45F295611417B4B6DA6324EA")
}


rule sologame_a: fakeapps
{
	meta:
		description = "This rule detetcs fake apps"
		sample = "b00a77445af14576cdfbed6739bbb80338893975d3c5ff5d9773e3565a373a30"
	strings:
		$ic = "res/drawable/ic.png"
	condition:
		$ic and cuckoo.network.dns_lookup(/aff.mclick.mobi/)
}


rule fake_apps_a
{
	meta:
		description = "Fake Apps"
	strings:
		$a = "150613072127Z"
		$b = "421029072127Z0I1"
	condition:
		$a or $b
}


rule FakeFacebook_a
{
	meta:
		description = "Fake Facebook applications"
	condition:
		androguard.app_name("Facebook") and
		not androguard.certificate.sha1("8A3C4B262D721ACD49A4BF97D5213199C86FA2B9")	
}


rule FakeFlashPlayer_a
{
	meta:
		description = "Fake FlashPlayer apps"
	condition:
		androguard.app_name("Flash Player") or
		androguard.app_name("FlashPlayer") or
		androguard.app_name("Flash_Player") or
		androguard.app_name("Flash update")
}


rule koodous_p: official
{
	meta:
		description = "This ruleset detects a family of smsfraud trojans"
		sample = "110f2bd7ff61cd386993c28977c19ac5c0b565baec57272c99c4cad6c4fc7dd4"
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.certificate.sha1("4B01DF162934A8E6CF0651CE4810C83BF715A55D") 
}


rule Sparkasse_a: Fake Banking App
{
	condition:
		(
		  androguard.app_name("Sparkasse") 
		  or androguard.app_name("Sparkasse+")
		  or androguard.app_name("Sparkasse+ Tablet")
		  or androguard.app_name("Sparkasse Update")
		  or androguard.app_name("Sparkasse Verify")
		  or androguard.app_name("Sparkasse Sicherheitszertifikat")
		  or androguard.app_name("Sparkasse Zertifikat")
		  or androguard.app_name("Sparkasse Sicherheit")
		)
		and not androguard.certificate.sha1("0DADCA40A960FF65BB72104378BE92DB4051B28B")
}
rule Postbank_a: Fake Banking App
{
	condition:
		(
		  androguard.app_name("Finanzassistent")
		  or androguard.app_name("Postbank")
		  or androguard.app_name("Postbank Finanzassistent")
		  or androguard.app_name("Postbank Sicherheitszertifikat")
		  or androguard.app_name("Postbank Verify")
		  or androguard.app_name("Postbank Update")
		  or androguard.app_name("Postbank Zertifikat")
		  or androguard.app_name("Postbank Sicherheit")
		) 
		and not androguard.certificate.sha1("73839EC3A528910B235859947CC8424543D7B686")
}
rule Volksbank_a: Fake Banking App
{
	condition:
		(
		   androguard.app_name("VR-Banking")
		   or androguard.app_name("Volksbank")
		   or androguard.app_name("Volksbank Update")
		   or androguard.app_name("Volksbank Verify")
		   or androguard.app_name("Volksbank Sicherheitszertifikat")
		   or androguard.app_name("Volksbank Zertifikat")
		   or androguard.app_name("Volksbank Sicherheit")
		)
		and not androguard.certificate.sha1("ADDB5ED43A27660E41ACB1D39E85DDD7B9C9807C")
}
rule Commerzbank_a: Fake Banking App
{
	condition:
		(
		   androguard.app_name("Commerzbank")
		   or androguard.app_name("Commerzbank Update")
		   or androguard.app_name("Commerzbank Verify")
		   or androguard.app_name("Commerzbank Sicherheitszertifikat")
		   or androguard.app_name("Commerzbank Zertifikat")
		   or androguard.app_name("Commerzbank Sicherheit")
		)
		and not ( androguard.certificate.sha1("1BA105AB48190B0369A07BA7E9AA2E68952A2DD1") 
			or androguard.certificate.sha1("B7921B2DFC5D6DEB60ED9F6E969CD4D6DBDF2456")
		)
}
rule DKBpushTAN_a: Fake Banking App
{
	condition:
		(
		  androguard.app_name("DKB-pushTAN")
		  or androguard.app_name("TAN2go")
		  or androguard.app_name("DKBTAN2go")
		) 
		and not androguard.certificate.sha1("B4199718EAA0E676755AF77419FB59ABF7FECE00")
}


rule fake_playstore_a
{
	meta: 
		description = "Yara detection for Fake Google Playstore"
		samples = "1c19aedabe7628594c40a239369dc891d6b75ba4562425267ea786a8a3dcdf98"		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "contact4SMS" nocase
		$str_2 = "contacts2up" nocase
		$str_3 = "com.google.game.store.close"
		$str_4 = "/webmaster/action/"
	condition:
		androguard.certificate.sha1("DC517E3302B426FA57EDD9B438C02F094D17976B") or 
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and 
		all of ($str_*)
}


rule koodous_q: official
{
	meta:
		description = "Ads and pron. Gets to remote host(porn) http://hwmid.ugameok.hk:8803/vvd/"
	strings:
		$a = "http://hwmid.ugameok.hk:8803/vvd/main?key="
	condition:
		androguard.certificate.sha1("C2:E4:C2:C7:AA:E9:ED:9C:C9:4B:B0:12:BA:DB:52:26:D1:27:87:42") or $a
}


rule clicker_c: url
{
	meta:
		description = "This rule detects the Fake installer malwares by using visited URL"
		sample = "aa560b913446d45d29c5c0161bbe6e4c16f356afd818af412c56cde0ae5a6611"
	condition:
		cuckoo.network.http_request(/^http?:\/\/suitepremiumds\.ru/) or 
		cuckoo.network.http_request(/suitepremiumds\.ru/) or 
		androguard.url(/^http?:\/\/suitepremiumds\.ru/) or 
		androguard.url(/suitepremiumds\.ru/)
}


rule fake_installer_a: orggoogleapp
{
	condition:
		androguard.certificate.sha1("86718264E68A7A7C0F3FB6ECCB58BEC546B33E22")				
}


rule fake_market_a
{
	condition:
		androguard.package_name("com.minitorrent.kimill") 
}


rule minecraft_a
{
	condition:
		( androguard.app_name("Minecraft: Pocket Edition") or 
			androguard.app_name("Minecraft - Pocket Edition") )
		and not androguard.package_name("com.mojang.minecraftpe")
}


rule pokemongo_a: fake
{
	meta:
		description = "This rule detects fakes Pokemon Go apps "
		sample = ""
	condition:
		(androguard.package_name("com.nianticlabs.pokemongo") or androguard.app_name("Pokemon GO")) and not
		androguard.certificate.sha1("321187995BC7CDC2B5FC91B11A96E2BAA8602C62")
}


rule FakeWhatsApp_a
{
	meta:
		description = "Fake WhatsApp applications"
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}


rule FakeApp_a
{
	meta:
		description = "FakeApp installer from fake developers"
		sample = "047b5ae5d7dddc035076b146e8d4548c877c78ab10686e795a354d497f72c321"
  condition:
    androguard.certificate.sha1("70A979A8E7C51EF068B7C41C2ECD2FDDB333C35C") or
	androguard.certificate.sha1("762E0CF7220044FC3374E05C395DF2C4FA4CBD9B") or
	androguard.certificate.sha1("ABB4A1C5B5E1F8E7208E20C32DA3F92D20CC5F4F") or
	androguard.certificate.sha1("F0A46A31E0446DC68CF270249E2111C6FA5A29BF") or
	androguard.certificate.sha1("CA6AAAD3963325E26734455482780ED2599B71AD") or
	androguard.certificate.sha1("595E399D88FD8C526748C39369CB546C3D2C8871") or
	androguard.certificate.subject(/Attacker Inc\./) or
	androguard.certificate.subject(/Attacker corp\./)
}
rule AddsDomains_a
{
	meta:
		description = "Fraudulent domains used in Ads Campaigns"
		sample = "3516eb210aad7f05c8c2d5485905308714d9fe6c898cfd8e35cb247475846261"
	strings:
		$1 = "zzwx.ru/" wide ascii
		$2 = "zwx.ru/" wide ascii	
		$3 = "sppromo.ru/" wide ascii
		$4 = "tdslsd.ru/" wide ascii
		$5 = "cldrm.com/" wide ascii
		$6 = "clmbtrk.com/" wide ascii
		$7 = "cldlr.com/" wide ascii
		$8 = "wezzx.ru/" wide ascii
		$9 = "leno.ml/" wide ascii		
		$10 = "winbv.nl/" wide ascii
	condition:
		1 of them or
		cuckoo.network.dns_lookup(/zzwx.ru/) or
		cuckoo.network.dns_lookup(/zwx.ru/) or
		cuckoo.network.dns_lookup(/sppromo.ru/) or
		cuckoo.network.dns_lookup(/tdslsd.ru/) or
		cuckoo.network.dns_lookup(/cldrm.com/) or
		cuckoo.network.dns_lookup(/clmbtrk.com/) or
		cuckoo.network.dns_lookup(/cldlr.com/) or
		cuckoo.network.dns_lookup(/wezzx.ru/) or
		cuckoo.network.dns_lookup(/leno.ml/) or
		cuckoo.network.dns_lookup(/winbv.nl/)		
}


rule blacklisted_strings_a: jcarneiro
{
	meta:
		description = "This rule fake apps strings"
	strings:
		$a = "application has been update to run the application"
		$b = "com.evasoft.siteredrect"
		$c = "Correct update do only with 3G/4G internet connection. Please turn-off WiFi-connection and click Update button"
		$d = "disable WiFi, and then click Download"
		$e = "download [new version!]"
		$f = "for app there is an update"
		$g = "install and open 3 of our completely free apps"
		$h = "install and open 3 of our complety free apps"
		$i = "Install apk....please wait!"
		$j = "necassary to make review and rate 5 stars"
		$k = "necessary to make review and rate 5 stars"
		$l = "need to download 3 free games"
		$m = "Please update the version of the aptoide client"
		$n = "rate us with 5 stars to open the app"
		$o = "Thank you for choosing APTOIDE"
		$p = "Thank you that you chose Aptoide"
		$q = "The button INSTALL will be atcive after installation of the application below"
		$r = "This free version is supported by Ads, you need to check some ads to continue"
		$s = "TO INSTALL GAME, CLICK TO ACTIVATE"
		$t = "turn off Wi-Fi and turn on 3G"
		$u = "You have 18 year old?"
		$v = "you have not opened at least once the 3 applications you just installed"
		$w = "You need to check ads before continue."
	condition:
		any of them
}


rule AgeWap_a
{
	meta:
		description ="Rule to detect AgeWap apps. They send fraudulent SMS - Very small size always."
	condition:
		androguard.certificate.issuer(/C=RU\/ST=Unknown\/L=Moscow\/O=AgeWap\/OU=AgeWap Corp\.\/CN=AgeWap/) and androguard.permission(/android.permission.SEND_SMS/)
}
rule Londaniga_a
{
	meta:
		description = "Rule to detect Londaniga fake apps. SMS Fraud in most."
	condition:
		androguard.certificate.issuer(/lorenz@londatiga.net/) and androguard.permission(/android.permission.SEND_SMS/)		
}
rule Londaniga2_a: urls
{
	meta: 
		description = "IPs receiving info from user in Londaniga apps." 
	strings:
		$a = "http://211.136.165.53/adapted/choose.jsp?dest=all&chooseUrl=QQQwlQQQrmw1sQQQpp66.jsp"
		$b = "http://211.136.165.53/wl/rmw1s/pp66.jsp"
	condition:
		all of them
}
rule gsr_a
{
	meta:
		description = "Fakes Apps (Instagram Hack) and adds very intrusive ads"
		sample = "42a5fe37f94e46b800189d7412a29eee856248f9a2ebdc3bc18eb0c6ae13b491"
	condition:
		androguard.certificate.sha1("943BC6E0827F09B050B02830685A76734E566168")
}
rule smsReg_a {
	strings:
		$mmmm = "http://zhxone.com/"
		$oooo = "http://coco.zhxone.com"
		$nnnn = "http://tools.8282.net"
		$jjjj = "http://coco.zhxone.com/tools/datatools"
 		$pppp = "www.zhxone.com/service.php?api=apkinstall&pk=%s&aid=1000002"
 		$qqqq = "http://auto.zhxone.com/adredirect.php?ct=%d&ag=%s&u=%s"
		$rrrr = "http://auto.zhxone.com/adredirect.php?ct=%d"
		$ssss = "http://tools.8782.net/stat.php?ac=upsts&did=%s&ag=%d&md=%s&sdk=%s&rel=%s&cp=%s&s=1"
		$tttt = "www.zhxone.com/service.php?api=uslog&n=hdus_start&u=%s"
		$uuuu = "http://tools.8782.net/stat.php?ac=uperr&did=%s&tg=%s&er=%s"
	condition:
		any of them
}
rule PornSMS_a {
	 condition:
	 	androguard.package_name("com.shenqi.video.ycef.svcr") or 
		androguard.package_name("com.shenqi.video.tjvi.dpjn)") or
		androguard.package_name("dxas.ixa.xvcekbxy") or
		androguard.package_name("com.video.ui") or 
		androguard.package_name("com.qq.navideo") or
		androguard.package_name("com.android.sxye.wwwl") or
		androguard.certificate.issuer(/llfovtfttfldddcffffhhh/)
		}


rule fakeav_a
{
	condition:
	  androguard.package_name("com.hao.sanquanweishi") or
	  androguard.certificate.sha1("1C414E5C054136863B5C460F99869B5B21D528FC")
}


rule Android_FakeBank_Fanta_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android FakeBank_Fanta"
		source = "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/"
	condition:
		androguard.service(/SocketService/i) and 
		androguard.receiver(/MyAdmin/i) and 
		androguard.receiver(/Receiver/i) and 
		androguard.receiver(/NetworkChangeReceiver/i)
}


rule facebook_a: fakebook
{
	meta:
		description = "Detects fake facebook applications"
		hash_0 = "7be33c2d27121968d2f7081ae2b04965238a3c15c7aae62d006f629d64e0b58e"
		hash_1 = "c1264c689393880361409eb02570fd49bec91c88569d39062e13c0c8ae0e1806"
		hash_2 = "70d5cc909d5718674474a54b44f83bd194cbdd2d99354d52cd868b334fb5f3de"
		hash_3 = "38e757abd5e015e3c3690ea0fdc2ff1e04b716651645a8c4ca6a63185856fe29"
		hash_4 = "ba0b8fe37b4874656ad129dd4d96fdec181e2c3488985309241b0449bb4ab84f"
		hash_5 = "7be33c2d27121968d2f7081ae2b04965238a3c15c7aae62d006f629d64e0b58e"
		hash_6 = "c1264c689393880361409eb02570fd49bec91c88569d39062e13c0c8ae0e1806"
		hash_7 = "7345c3124891b34607a07e93c8ab6dcbbf513e24e936c3710434b085981b815a"
	condition:
		androguard.app_name("Facebook") and
		not androguard.package_name(/com.facebook.katana/) and 
		not androguard.certificate.issuer(/O=Facebook Mobile/)
}


rule FakeCMSecurity_a: Certs
{
    condition:
        androguard.certificate.sha1("2E66ED3E9EE51D09A8EFCE00D32AE5E078F1F1B6")
}


rule fake_framaroot_a
{
	meta:
		description = "This rule detects fake framaroot apks"
		sample = "41764d15479fc502be6f8b40fec15f743aeaa5b4b63790405c26fcfe732749ba"
	condition:
		androguard.app_name(/framaroot/i) and
		not androguard.certificate.sha1("3EEE4E45B174405D64F877EFC7E5905DCCD73816")
}


rule fakeInstaller_b
{
	meta:
		description = "This rule detects application that simulate an Installer"
		sample = "e8976d91cbfaad96f9b7f2fd13f2e13ae2507e6f8949e26cbd12d51d7bde6305"
	strings:
		$a = "res/raw/animation.txtPK"
		$b = "res/raw/roolurl.txtPK"
		$c = "cpard/ivellpap"
		$d = "http://wap4mobi.ru/rools.html"
		$e = "res/raw/conf.txtPK"
	condition:
		all of them
}
rule fakeinstaller_sms_a
{
	strings:
		$a = "http://sms24.me" wide
		$b = "http://sms911.ru" wide
		$c = "smsdostup.ru" wide
	condition:
		any of them
}


rule FakeInst_a
{
	meta:
        description = "FakeInst evidences"
	strings:
		$1 = "res/raw/mccmnc.txt" wide ascii
		$2 = "Calculated location by MCCMNC" wide ascii
		$3 = "getCost" wide ascii
   	condition:
		all of them
}
rule FakeInst_certs_a
{
	meta:
		description = "FakeInst installer from fake developers"
		sample = "acce1154630d327ca9d888e0ecf44a1370cf42b3b28a48446a9aaaec9ec789c3"
	condition:
		androguard.certificate.sha1("C67F8FC63E25C1F2D3D3623210D126BC96AFEE69") or
		androguard.certificate.sha1("FB2FD4D89D7363E6386C865247825C041F23CDEB") or
		androguard.certificate.sha1("9AD4DB5F64C6B12106DCAE54A9759154C56E27E1") or
		androguard.certificate.sha1("0A721AF65BBB389EA9E224A59833BD3FD92F4129") or
		androguard.certificate.sha1("5D66125A5FAE943152AE83D5787CDCFD1C579F4E")	or	
		androguard.certificate.sha1("2260A1A17C96AF2C8208F0C0A34CF3B87A28E960")
}
rule FakeInst_offers_xmls_a
{
	meta:
        description = "FakeInst evidences offers XML"
	strings:
		$0 = "strings.xml" wide ascii
		$1 = "app_name" wide ascii
		$2 = "apps_dir_wasnt_created" wide ascii
		$3 = "dialog_file_downloads_text" wide ascii
		$4 = "dialog_no_button" wide ascii
		$5 = "dialog_yes_button" wide ascii
		$6 = "download_file" wide ascii
		$7 = "error_sms_sending" wide ascii
		$8 = "full_offerts_text" wide ascii
		$9 = "i_disagree_offert" wide ascii
   	condition:
		all of them
}
rule FakeInst_v2_a
{
	meta:
        description = "FakeInst evidences v2"
	strings:
		$1 = "loadSmsCountabc123" wide ascii
		$2 = "loadSmsCountMethod" wide ascii
		$3 = "sentSms" wide ascii
		$4 = "getSentSms" wide ascii
		$5 = "maxSms" wide ascii
   	condition:
		all of them
}
rule FakeInst_v3_a
{
	meta:
        description = "FakeInst evidences v3"
	strings:
		$sa0 = "data.db" wide ascii
		$sa1 = "sms911.ru" wide ascii
		$sb0 = "agree.txt" wide ascii		
		$sb1 = "topfiless.com" wide ascii
   	condition:
		all of ($sa*) or all of ($sb*)
}
rule FakeInst_v4_a
{
	meta:
        description = "FakeInst evidences v4"
	strings:
		$1 = "android/telephony/gsm/SmsManager" wide ascii
		$2 = "getText123" wide ascii
		$3 = "setText123" wide ascii
		$4 = "text123" wide ascii
   	condition:
		all of them
}
rule FakeInst_domains_a
{
	meta:
        description = "FakeInst evidences domains"
	strings:
		$1 = "myfilies.net/?u=" wide ascii
		$2 = "m-love12.net/?aid=" wide ascii
		$3 = "androidosoft.ru/engine/download.php?id=" wide ascii
		$4 = "sellapis.ru/am/files/" wide ascii
		$5 = "myapkbox.cu.cc/market.php?t=" wide ascii
		$6 = "wap4mobi.ru/rools.html" wide ascii
		$7 = "filesmob.ru/getfile.php?fl=" wide ascii			
   	condition:
		1 of them
}


rule fakeinstaller_a
{
	meta:
		sample = "e39632cd9df93effd50a8551952a627c251bbf4307a59a69ba9076842869c63a"
	condition:
		androguard.permission(/com.android.launcher.permission.INSTALL_SHORTCUT/)
		and androguard.permission(/android.permission.SEND_SMS/)
		and androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")
		and androguard.certificate.issuer(/hghjg/)
}


rule Ransom_a {
	meta: 
		description = "ransomwares"	
	strings:
		$a = "!2,.B99^GGD&R-"
		$b = "22922222222222222222Q^SAAWA"
	condition:
		$a or $b
}
rule fakeInstalls_a {
	meta:
	 description = "creates fake apps (usually low sized) for malicious purposes."
	condition:
		androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")
}


rule FakePlayerSMS_a
{
	condition:
		androguard.app_name(/PornoPlayer/) and
		androguard.permission(/SEND_SMS/)		
}


/*
 * Regla para detectar la ocurrencia de nuestra muestra 
rule FakePostBank_a {
meta:
descripton= "Regla para Detectar Fake Post Bank"
strings:
		$a = "http://185.62.188.32/app/remote/"
		$b = "intercept_sms"
		$c = "unblock_all_numbers"
		$d = "unblock_numbers"
		$e = "TYPE_INTERCEPTED_INCOMING_SMS"
		$f = "TYPE_LISTENED_INCOMING_SMS"
	condition:
		$a and $b and ($c or $d or $e or $f)
}


rule Trojan_SberBank_a:Generic {
	strings:
		$ = "SHA1-Digest: 0RYXrwza/VlrQipZh52pDBGYSv4=" // res/layout/html_win.xml
		$ = "SHA1-Digest: 2MulKCZR+tONx7LwGwYj0iu6p1k=" // res/layout/chat_sent.xml
		$ = "SHA1-Digest: 4igVIY5xayNxe5Sde9RKcRtwCZM=" // res/layout-v17/chat_interface.xml
		$ = "SHA1-Digest: 9XFO5nLfmU2zFKMEg5WZpgf+QDs=" // res/menu-v11/sba.xml
		$ = "SHA1-Digest: EpKx2fb1krx+1ur7MvFMXS/kMxA=" // res/drawable/border_white.xml
		$ = "SHA1-Digest: IJrFgK4WHwDca+LzUXjqZp2pay0=" // res/xml/shhtdi.xml
		$ = "SHA1-Digest: Krc08hysIogRi8pojcDE29oQCnI=" // res/layout/chat_receive.xml
		$ = "SHA1-Digest: MPo0HYhkXD7dsSBWAf8Rszo0bdI=" // res/layout-v17/chat_row.xml
		$ = "SHA1-Digest: P/3/FuaWSmTJzhEqPKhcSn4X00Y=" // res/xml/rotatter.xml
		$ = "SHA1-Digest: R1Vm5lb43YlHLnwI1pO68trQnxw=" // res/layout/adm_win.xml
		$ = "SHA1-Digest: j8bj2Jwy/rSyyR3pMorEje8InWI=" // res/xml/ashp.xml
		$ = "SHA1-Digest: oC1yBCAMYEJUij+pELT2JTSNizg=" // res/xml/da.xml
		$ = "SHA1-Digest: rUYGYMmoO8HjIdBex+fX/xLL0t0=" // res/layout/chat_interface.xml
		$ = "SHA1-Digest: yJi5Vu0G3AqXbLAdSlIgvxYQaw8=" // res/anim/dialog_close.xml
		$ = "SHA1-Digest: zY4Ma7dxptRI8YdoKrdIegQ4a9o=" // res/anim/dialog_open.xml
		$a = "Sberbank" nocase
	condition:
		all of ($) and $a
}


rule rest_a
{
	strings:
		$ = "cards, you can resolve the confusion within your heart. Every card has two" 
	  	$ = "sides, representing the Pros and Cons of a subject. All the answers are" 
		$ = "First of all, this is a free software, but due to the high development costs" 
	condition:
		all of them
}


rule FakeUpdate_a
{
    condition:
        androguard.certificate.sha1("45167886A1C3A12212F7205B22A5A6AF0C252239")
}


rule fake_google_chrome_a
{
	meta:
		description = "This rule detects fake google chrome apps"
		sample = "ac8d89c96e4a7697caee96b7e9de63f36967f889b35b83bb0fa5e6e1568635f5"
	condition:
		androguard.package_name("com.android.chro.me")
}


rule FalseGuide_a
{
	meta:
		description = "http://blog.checkpoint.com/2017/04/24/falaseguide-misleads-users-googleplay/"
		sample = "9d8888f3e8a3ce16108827333af3447c"
	condition:
	  (androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")and
	  androguard.filter("android.intent.action.BOOT_COMPLETED")and
	  androguard.filter("android.intent.action.MAIN")and
	  androguard.filter("android.intent.action.QUICKBOOT_POWERON")and
	  androguard.filter("com.android.vending.INSTALL_REFERRER")and
	  androguard.filter("com.google.android.c2dm.intent.RECEIVE")and
	  androguard.filter("com.google.android.c2dm.intent.REGISTRATION")and
	  androguard.receiver("com.google.android.gms.measurement.AppMeasurementInstallReferrerReceiver")and
	  androguard.receiver("com.google.android.gms.measurement.AppMeasurementReceiver")and
	  androguard.receiver("com.google.firebase.iid.FirebaseInstanceIdInternalReceiver")and
	  androguard.receiver("com.google.firebase.iid.FirebaseInstanceIdReceiver")and
	  androguard.receiver("com.yandex.metrica.MetricaEventHandler")and
	  androguard.receiver(/AdminReceiver/)and
	  androguard.receiver(/BootReceiver/)and
	  androguard.service("com.flymob.sdk.common.server.FlyMobService")and
	  androguard.service("com.google.android.gms.measurement.AppMeasurementService")and
	  androguard.service("com.google.firebase.iid.FirebaseInstanceIdService")and
	  androguard.service("com.google.firebase.messaging.FirebaseMessagingService")and
	  androguard.service("com.yandex.metrica.MetricaService") and
	  androguard.service(/MessagingService/) and
	  androguard.service(/MyService/)) or
	  androguard.certificate.sha1("FBE76CAE248E420E0D02F3E7362F8C3C1CEC75C4") or
	  androguard.certificate.sha1("630CC5A2192230B02BE7ED89164514D1E971E4BA") or
	  androguard.certificate.sha1("D0A83D20D80C29F35A84FBDE45F61E2B867C199B")
}


rule feckeny_a
{
	meta:
		description = "This ruleset looks for feckeny's apps"
	condition:
		androguard.certificate.issuer(/feckeny/) 
		or androguard.certificate.subject(/feckeny/)
}


rule qihoo360_a: packer
{
	meta:
		description = "Qihoo 360"
	strings:
		$a = "libprotectClass.so"
	condition:
		$a 
}
rule ijiami_a: packer
{
	meta:
		description = "Ijiami"
	strings:
		$old_dat = "assets/ijiami.dat"
		$new_ajm = "ijiami.ajm"
		$ijm_lib = "assets/ijm_lib/"
	condition:
		$old_dat or $new_ajm or $ijm_lib
}
rule naga_a: packer
{
	meta:
		description = "Naga"
	strings:
		$lib = "libddog.so"
	condition:
		 $lib
}
rule alibaba_a: packer
{
	meta:
		description = "Alibaba"
	strings:
		$lib = "libmobisec.so"
	condition:
		 $lib
}
rule medusa_a: packer
{
	meta:
		description = "Medusa"
	strings:
		$lib = "libmd.so"
	condition:
		$lib
}
rule baidu_a: packer
{
	meta:
		description = "Baidu"
	strings:
		$lib = "libbaiduprotect.so"
		$encrypted = "baiduprotect1.jar"
	condition:
		$lib or $encrypted
}
rule pangxie_a: packer
{
	meta:
		description = "PangXie"
	strings:
		$lib = "libnsecure.so"
	condition:
	 	$lib
}


rule flash_malware_a
{
	meta:
		description = "Flash Malware Dvxew"
		sample = "c8868f751c278fb80e8cc0479cb142b354c7ee316735a05fc1a3d972269a2650"
	strings:
		$a = "Titular de la tarjeta"
	condition:
		androguard.package_name("xgntkxwj.teetwvmofhrp") and
		androguard.certificate.sha1("E40D76BA3A504889014A91FBC178A4B19DEC0408") and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		$a
}


rule fraudulent_developers_a: airpush
{
	condition:
		androguard.certificate.issuer(/tegyhman/) 
		or androguard.certificate.issuer(/tengyhman/)
		or androguard.certificate.issuer(/pitorroman/) 
		or androguard.certificate.subject(/pitorroman/)
}


rule Fushicho_a: official
{
	meta:
		description = "http://blog.avlsec.com/2016/09/3788/fushicho/"
	condition:
		androguard.url(/mmchongg\.com/) or
		androguard.url(/yggysa\.com/) or
		cuckoo.network.dns_lookup(/mmchongg/) or
		cuckoo.network.dns_lookup(/yggysa/) or
		cuckoo.network.http_request(/abcll0/) or
		cuckoo.network.http_request(/us:9009\/gamesdk\/doroot\.jsp\?/)
}


rule gaga01_a:SMSSender
{
	condition:
		cuckoo.network.dns_lookup(/gaga01\.net/)
}


rule unknown_a
{
	meta:
		sample = "ee05cbd6f7862f247253aa1efdf8de27c32f7a9fc2624c8e82cbfd2aab0e9438"
		search = "package_name:com.anrd.bo"
	strings:
		$a = "543b9536fd98c507670030b9" wide
		$b = "Name: assets/su"
	condition:
		all of them
}


rule banker_a: generic
{
	meta:
		description = "This rule detects the Generic banker asking for credit card information where GooglePlay is launched"
		sample = "4782faa6ae60a1d31737385196deeffc920cfb6c4f1151947f082c5d78846549"
	strings:
		$visa_1 = "res/drawable/cvc_visa.gifPK"
		$visa_2 = "cvc_visa"
		$mastercard_1 = "res/drawable/cvc_mastercard.gifPK"
		$mastercard_2 = "cvc_mastercard"
		$google_play = "Google Play"
	condition:
		(all of ($visa_*) or all of ($mastercard_*)) and $google_play
}


rule Generic_a: Banker
{
	meta:
		description = "Generic Rule to identify banker trojans"
	strings:
		$gp = "Google Play" nocase
		$mastercard_1 = "cvc_mastercard" nocase
		$mastercard_2 = "mastercard_cvc" nocase
		$visa_1 = "cvc_visa" nocase
		$visa_2 = "visa_cvc" nocase
		$amex_1 = "cvc_amex" nocase
		$amex_2 = "amex_cvc" nocase
	condition:
		$gp and 
		(
			(1 of ($mastercard_*)) or 
			(1 of ($visa_*)) or 
			(1 of ($amex_*))
		) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)	
}


rule genericSMS_a: smsFraud
{
	meta:
		sample = "3fc533d832e22dc3bc161e5190edf242f70fbc4764267ca073de5a8e3ae23272"
		sample2 = "3d85bdd0faea9c985749c614a0676bb05f017f6bde3651f2b819c7ac40a02d5f"
	strings:
		$a = "SHA1-Digest: +RsrTx5SNjstrnt7pNaeQAzY4kc="
		$b = "SHA1-Digest: Rt2oRts0wWTjffGlETGfFix1dfE="
		$c = "http://image.baidu.com/wisebrowse/index?tag1=%E6%98%8E%E6%98%9F&tag2=%E5%A5%B3%E6%98%8E%E6%98%9F&tag3=%E5%85%A8%E9%83%A8&pn=0&rn=10&fmpage=index&pos=magic#/channel"
		$d = "pitchfork=022D4"
	condition:
		all of them
}
rule genericSMS2_a: smsFraud
{
	meta:
		sample = "1f23524e32c12c56be0c9a25c69ab7dc21501169c57f8d6a95c051397263cf9f"
		sample2 = "2cf073bd8de8aad6cc0d6ad5c98e1ba458bd0910b043a69a25aabdc2728ea2bd"
		sample3 = "20575a3e5e97bcfbf2c3c1d905d967e91a00d69758eb15588bdafacb4c854cba"
	strings:
		$a = "NotLeftTriangleEqual=022EC"
		$b = "SHA1-Digest: X27Zpw9c6eyXvEFuZfCL2LmumtI="
		$c = "_ZNSt12_Vector_baseISsSaISsEE13_M_deallocateEPSsj"
		$d = "FBTP2AHR3WKC6LEYON7D5GZXVISMJ4QU"
	condition:
		all of them
}
rule genericSMS3_a: smsFraud
{
	meta:
		sample = "100de47048f17b7ea672573809e6cd517649b0f04a296c359e85f2493cdea366"
		sample2 = "0c5392b7ec1c7a1b5ec061f180b5db4d59b476f7f6aaa1d034b7c94df96d4a36"
		sample3 = "1002ab2d97ee45565cdec4b165d6b4dcd448189201adad94ea8152d8a9cadac3"
	strings:
		$a = "res/drawable-xxhdpi/abc_textfield_search_selected_holo_dark.9.pngPK"
		$b = "SHA1-Digest: Jxn4OLlRA7rJLn731JTR4YDWdiY="
		$c = "\\-'[%]W["
		$d = "_ZN6N0Seed10seedStatusE"
	condition:
		all of them
}


rule geohotS4_a
{
	meta:
		description = "Geohot S4"
	strings:
		$a = {7C 44 79 44 20 1C FF F7 B0 EE 20 4B 06 1C 01}
	condition:
		$a
}


rule GGTRACK_detecrot_a: trojan
{
	condition:
		androguard.url("http://ggtrack.org/") or
		androguard.url(/ggtrack\.org/) 
}


rule ggtracker_a: trojan
{
	meta:
		description = "Android.Ggtracker is a Trojan horse for Android devices that sends SMS messages to a premium-rate number. It may also steal information from the device."
		sample = "8c237092454584d0d6ae458af70dc032445b866fd5913979bbad576f42556577"
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.url("http://ggtrack.org/SM1c?device_id=")
}


rule ghostpush_a
{
	meta:
		sample = "bf770e42b04ab02edbb57653e4e0c21b2c983593073ad717b82cfbdc0c7d535b"
	strings:
		$a = "assets/import.apkPK"
		$b = "assets/protect.apkPK"
	condition:
		all of them
}


rule Android_GMBot_Variant_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "08-November-2016"
		description = "This rule will be able to tag all GMBot variants."
		source = ""
	condition:
		androguard.service(/\.HeadlessSmsSendService/i) and
        androguard.receiver(/\.PushServiceRcvr/i) and
		androguard.receiver(/\.MmsRcvr/i) and
		androguard.receiver(/\.BootReceiver/i)
}


rule Godless_malware_a
{
	meta:
		description = "GODLESS Mobile Malware"
	strings:
		$a = "android.intent.action.SCREEN_OFF"
		$b = "system/app/AndroidDaemonFrame.apk"
		$c = "libgodlikelib.so"
	condition:
		$a and $b and $c
}


rule Godlike_a
{
	meta:
		description = "This rule detects samples belonging to Godlike malware"
		sample = "61b8f90fec5a3179978844c9336890dcc429207363181596ae9ee2c7ef6ab6b6"
	strings:
		$a = "lib/armeabi/libgodlikelib.so"
		$b = "lib/armeabi-v7a/libgodlikelib.so"
	condition:
		$a or $b
}


rule gunpoderType1_a
{
	meta:
		sample = "4a0da8da1116fbc6d85057110d1d8580dcc5f2746e492415f0f6c19965e71c9c"
		sample2 = "68d3548306c9667b4d1a6e483cbf2d2f7566213a639316512d4958ff0b2e8f94"
		sample3 = "77ee18a207bb79c86fa5976b9f5a4fe36f4ecd429dc9846fa71c6585b6df85b5"
		sample4 = "844ba4b96b7f1df89a3e31544cf22bac9acf1ab97a4d9972daf8aa3fbb149c37"
		reference = "http://researchcenter.paloaltonetworks.com/2015/07/new-android-malware-family-evades-antivirus-detection-by-using-popular-ad-libraries"
	strings:
		$a = "stopWaitSMS"
		$b = "saldo de PayPal o su tarjeta de"
		$c = "name=\"cc_card_expires\">Expires MM"
		$d = "CardIOActivity"
	condition:
		all of them
}
rule gunpoderType2_a
{
	meta:
		sample = "2788c90a320f3cd8fac34a223b868c830ce2b3702b648bcecc21b3d39d3618f3"
		sample2 = "99ad2bb26936a7178bc876f1cdc969c8b0697f4f63f3bdd29b0fff794af4b43c"
		sample3 = "2c5251ce74342d0329dd8acc5a38c2a96a1d6ee617857aca8d11e2e818e192ce"
		sample4 = "bac759e73bf3b00a25ff9d170465219cb9fb8193adf5bbc0e07c425cc02a811d"
		reference = "http://researchcenter.paloaltonetworks.com/2015/07/new-android-malware-family-evades-antivirus-detection-by-using-popular-ad-libraries"
	strings:
		$a = "\"Return of the Invaders\""
		$b = "cmd_proxy_destroy"
		$c = "mhtu119.bin"
		$d = "robocopu  \"Robocop (US revision 1)\""
	condition:
		all of them
}
rule gunpoderType3_a
{
	meta:
		sample = "00872f2b17f2c130c13ac3f71abb97a9f7d38406b3f5ed1b0fc18f21eaa81b50"
		sample2 = "28b3bd3b9eb52257c0d7709c1ca455617d8e51f707721b834efe1ad461c083f0"
		sample3 = "df411483f2b57b42fd85d4225c6029000e96b3d203608a1b090c0d544b4de5b0"
		sample4 = "72c5fd8b77e6e02396ff91887ba4e622ab8ee4ea54786f68b93a10fcfa32f926"
		reference = "http://researchcenter.paloaltonetworks.com/2015/07/new-android-malware-family-evades-antivirus-detection-by-using-popular-ad-libraries"
	strings:
		$a = "email_md5"
		$b = "10.0.0.172"
		$c = "66The lastest version has been downloaded, install now ?"
		$d = "0aHR0cHM6Ly9hcGkuYWlycHVzaC5jb20vdjIvYXBpLnBocA=="
	condition:
		all of them
}


rule HackedScreen_a
{
    condition:
        androguard.activity(/.*\.HackedScreen/)
}


rule hacking_team_a: stcert
{
	meta:
		description = "This rule detects the apk related to hackingteam - These certificates are presents in mailboxes od hackingteam"
		samples = "c605df5dbb9d9fb1d687d59e4d90eba55b3201f8dd4fa51ec80aa3780d6e3e6e"
	strings:
		$string_a_1 = "280128120000Z0W1"
		$string_a_2 = "E6FFF4C5062FBDC9"
		$string_a_3 = "886FEC93A75D2AC1"
		$string_a_4 = "121120104150Z"
		$string_b_1 = "&inbox_timestamp > 0 and is_permanent=1"
		$string_b_2 = "contact_id = ? AND mimetype = ?"
		$string_c = "863d9effe70187254d3c5e9c76613a99"
		$string_d = "nv-sa1"
	condition:
		(any of ($string_a_*) and any of ($string_b_*) and $string_c and $string_d) or
		androguard.certificate.sha1("B1BC968BD4F49D622AA89A81F2150152A41D829C") or 	  
		androguard.certificate.sha1("3FEC88BA49773680E2A3040483806F56E6E8502E") or 
		androguard.certificate.sha1("C1F04E3A7405D9CFA238259730F096A17FCF2A4F") or 
		androguard.certificate.sha1("6961124AF170D9C0FF2B0571328CB6C71D6FD096") or 
		androguard.certificate.sha1("D198025BF15D7A19488B780E1B9AAD27BBE6C4A9")	or
		androguard.certificate.sha1("24575B8782D44CACB72253FEEB9DF811D0E12C37") or
		androguard.certificate.sha1("4E40663CC29C1FE7A436810C79CAB8F52474133B") or
		androguard.certificate.sha1("638814BFA962060E0869FFF41EDD2131C74B5001") or
		androguard.certificate.sha1("E4E57FC7ED86D6F4A8AB2C12C908FBD389C8387B") or
		androguard.certificate.sha1("C4CF31DBEF79393FD2AD617E79C27BFCF19EFBB3") or
		androguard.certificate.sha1("2125821BC97CF4B7591E5C771C06C9C96D24DF8F")
}


rule koodous_r: official
{
	meta:
		description = "hamrahpay.com"
	condition:
		androguard.url(/hamrahpay\.com/)
}




rule HiddenApp_a {
	strings:
	  	$ = /ssd3000.top/
		$ = "com.app.htmljavajets.ABKYkDEkBd"
	condition:
		1 of them
}


rule experimental_a
{
	strings:
		$ = "Th.Dlg.Fll13" nocase
		$ = "alluorine.info" nocase
		$ = "mancortz.info" nocase
		$ = "api-profit.com" nocase
		$ = "narusnex.info" nocase
		$ = "ronesio.xyz" nocase
		$ = "alluorine.info" nocase
		$ = "meonystic.info" nocase
		$ = "api-profit.com" nocase
		$ = "narusnex.info" nocase
		$ = "ngkciwmnq.info" nocase
		$ = "golangwq.info" nocase
		$ = "krnwhyvq.info" nocase
		$ = "nvewpvnid.info" nocase
		$ = "ovnwislxf.info" nocase
		$ = "deputizem.info" nocase
	condition:
		1 of them
}


rule hostingmy_a
{
	condition:
		androguard.certificate.issuer(/hostingmy0@gmail.com/)
}


rule HummingBad_a: malware
{
	meta:
		description = "https://www.checkpoint.com/downloads/resources/wp-hummingbad-research-report.pdf"
	strings:
		$a = "com.android.vending.INSTALL_REFERRER"
		$b = "Superuser.apk"
	condition:
		(androguard.package_name("Com.andr0id.cmvchinme") or
		androguard.package_name("Com.swiping.whale") or
		androguard.package_name("Com.andr0id.cmvchinmf") or
		androguard.package_name("com.quick.launcher")) and
		$a and $b
}


rule Android_HummingBad_a
{
	meta:
		description = "This rule detects Android.HummingBad"
		sample = "ed14da6b576910aaff07b37f5f5d283de8527a1b "
		source = "http://blog.checkpoint.com/2016/02/04/hummingbad-a-persistent-mobile-chain-attack/"
	strings:
		$string_1 = "assets/right_core.apk"
		$string_2 = "assets/right_core"
	condition:
		$string_1 or $string_2
}


rule HummingBad_b: urls
{
	meta:
		description = "This rule detects APKs in HummingBad Malware Chain"
		sample = "f2b98fd772e6ac1481f6c7bb83da9fdffc37d02b2f95e39567047d948a793e6d "
	strings:
		$string_1 = "assets/ResolverActivity.apk"
		$string_2 = "assets/readl"
		$string_3 = "assets/sailer.data"
		$string_4 = "assets/a.bmp"
		$string_5 = "assets/support.bmp"
		$string_6 = "assets/pc"
		$string_7 = "assets/daemon"
		$string_8 = "assets/ep"
		$string_9 = "assets/fx"
	condition:
		($string_1 and $string_3 and $string_2) or 
		($string_3 and $string_4 and $string_5 and $string_6 and $string_7) or 
		($string_6 and $string_7 and $string_8 and $string_9) or
		($string_6 and $string_7)
}


rule HummingBad_c: urls
{
	meta:
		description = "This rule detects APKs in HummingBad Malware Chain"
		sample = "72901c0214deb86527c178dcd4ecf73d74cac14eaaaffc49eeb00c7fb3343e79"
	strings:
		$string_1 = "assets/daemon.bmp"
		$string_2 = "assets/module_encrypt.jar"
		$string_3 = "assets/daemon"
	condition:
		($string_1 or $string_3) and $string_2
}


rule HummingWhale_a
{
	meta:
		description = "A Whale of a Tale: HummingBad Returns, http://blog.checkpoint.com/2017/01/23/hummingbad-returns/"
		sample = "0aabea98f675b5c3bb0889602501c18f79374a5bea9c8a5f8fc3d3e5414d70a6"
	strings:
		$ = "apis.groupteamapi.com"
		$ = "app.blinkingcamera.com"
	condition:
 		1 of them
}


rule Android_Malware_a: iBanking
{
	meta:
		author = "Xylitol xylitol@malwareint.com"
		date = "2014-02-14"
		description = "Match first two bytes, files and string present in iBanking"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3166"
	strings:
		$pk = {50 4B}
		$file1 = "AndroidManifest.xml"
		$file2 = "res/drawable-xxhdpi/ok_btn.jpg"
		$string1 = "bot_id"
		$string2 = "type_password2"
	condition:
		($pk at 0 and 2 of ($file*) and ($string1 or $string2))
}


rule iHandy_a
{
	meta:
		description = "Detects apps created by/conntected to iHandy"
	condition:
		cuckoo.network.dns_lookup(/appcloudbox.net/)
}


rule packers_e: Ijiami
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$Ijiami_1 = "libexecmain.so"
		$Ijiami_2 = "libexec.so"
		$Ijiami_3 = "ijiami.ajm"
	condition:
		all of them
}


rule infoLeak_a
{
	meta:
		description = "Get user info (IP, IMEI, SMS...) sent to remote address. "
	strings:
		$a = "http://imgsx.lingte.cc:8080/MTProject/MTContr?action=MTDetial&id="
		$b = "http://count.lingte.cc/IsInterface.php"
		$c = "http://imgsx.lingte.cc:8080/MTProject/MTContr?action=MTListUp&typeid="
	condition:
		$a or $b or $c
}


rule InfoStealer_a
{
	condition:
		androguard.package_name(/com.samples.servicelaunch/) and
		androguard.app_name(/ss/)
}


rule InjectionService_a
{
	meta:
		description = "This rule detects samples with possible malicious injection service"
		sample = "711f83ad0772ea2360eb77ae87b3bc45"
	condition:
		androguard.service(/injectionService/)
}


rule instagram_thief_phishing_a
{
	meta:
		description = "This rule detects the instagram password stealing in apks"
	strings:
		$string_a_1 = "tapinsta.ir/LoginPagei.html" nocase
		$string_a_2 = "mmbers.ir/FollowerGramNew/Instagram-Login" nocase
		$string_a_3 = "instagramapi.sinapps.ir" nocase
		$string_a_4 = "userplusapp.ir/instaup/LoginPage.html" nocase
		$string_a_5 = "instaplus.ir/instagram/login/index.php" nocase
		$string_a_6 = "hicell-developer.ir/OneFollow/Instagram-Login" nocase
		$string_a_7 = "x2net.ir/followerLike/login/instagram.html" nocase
		$string_a_8 = "cloobinsta.space/ClopInsta/Instagram-Login" nocase
		$string_a_9 = "login.instagramiha.org" nocase
		$string_a_10 = "elyasm.ir/cafeinstaz/LoginPage.html" nocase
		$string_a_11 = "takfollow.ir/instagram/login/index.php" nocase
		$string_a_12 = "instaclubbizans.com/InstaClub/Instagram-Login" nocase
		$string_a_13 = "login.instaregion.ir" nocase
		$string_a_14 = "hasan.followerapp.net/Instagram-Login" nocase
	condition:
		any of ($string_a_*)
}


rule Installer_a: banker
{
	meta:
		description = "Applications with Installer as an application name"
	condition:
		androguard.package_name("Jk7H.PwcD")
}


rule IRRat_a
{
	meta:
		author = "R"
		description = "https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/"
	condition:
		androguard.service(/botcontril/i) and
		androguard.url(/api.telegram.org\/bot/)
}


rule Jiaguo_a
{
	meta:
		description = "Jiaguo"
		sample = "0a108ace8c317df221d605b2e3f426e4b3712e480f8a780f3c9c61e7bc20c520"
	strings:
		$a = "assets/libjiagu.so"
		$b = "assets/libjiagu_x86.so"
	condition:
		$a and $b
}


rule JinBoShiPin_a: chinese_porn
{
	condition:
		androguard.app_name("\xe7\xa6\x81\xe6\x92\xad\xe8\xa7\x86\xe9\xa2\x91") // jin bo shi pin 277b8320ceb8481a46198f7b9491aef5e9cf54ecda32ca419d0f1aaa422f34cd
}


rule ransomware_a
{
	meta:
		description = "This rule detects ijimu.com and bluerobo.com see source"
		sample = "c2f5175eb7a9833bbba8ee6652e9fa69a0026fb18a614f96a4910380a5960d3f"
		source = "http://www.hotforsecurity.com/blog/android-malware-promises-porn-but-roots-device-and-installs-other-malware-13900.html"
	strings:
		$a = "http://root.ijimu.com:7354/"
		$b = "http://p.bluerobo.com:7354/"
		$c = "http://p2.bluerobo.com:7354/"
	condition:
		1 of them
}


rule android_joker_a {
    strings:
        $net = { 2F6170692F636B776B736C3F6963633D } // /api/ckwksl?icc=   
        $ip = "3.122.143.26"
    condition:
        $net or $ip 
}


rule ransomware_b
{
	meta:
		description = "This rule detects Ransomware"
		sample = "185c5b74d215b56ba61b4cebd748aec86e478c6ac06aba96d98eff58b24ee824"
		source = "https://twitter.com/LukasStefanko/status/683997678821322752"
	strings:
		$a = "findFrontFacingCamera"
		$c = "runReceiver"
		$d = "onCarete"
	condition:
		all of them
}


rule kemoge_a
{
	meta:
		description = "This rule detects kemoge trojan"
		sample = "4e9c3cf72da0c72aa4ef676d44f33576b6d83a66c5259760962ff0b6dcfab9c6"
		sample2 = "e0f3c5fee0b0d3bfc8f9f89dc4f4722eac3f2adea2c0403114b51ac1ca793927"
		sample3 = "5749b6beb4493adab453e26219652d968c760bea510196e9fd9319bc3712296b"
		reference = "https://www.fireeye.com/blog/threat-research/2015/10/kemoge_another_mobi.html"
	strings:
		$a = "f0h5zguZ9aJXbCZExMaN2kDhh6V0Uw=="
		$b = "147AF1A1DD6355A9"
		$c = "3u5ydeZkuIN7B1MIi0sjkwufUjbm"
		$d = "AndroidRTService.apk"
	condition:
		all of them
}


rule Kemoge_a: official
{
	meta:
		description = "This rule detects Kemoge aggresive Adware"
		sample = "0E012F69D493B7CC38FCAFCF495E0BD1290CA94B1AD043FCF255DF3AD5789834"
	strings:
		$a = {20 2D 20 57 72 6F 6E 67 20 50 61 73 73 77 6F 72 64 3F}
		$b = {23 23 23 20 4D 79 53 65 72 76 69 63 65 20 62 65 67 69 6E}
		$c = {34 37 41 46 31 41 31 44 44 36 33 35 35 41 39}
		$d = {42 61 73 65 4C 69 62}
		$e = {63 61 6E 6F 74}
		$f = {72 6F 6F 74 20 61 6C 72 65 61 64 79 20 64 6F 6E 65}
	condition:
		$a and $b and $c and $d and $e and $f
}
rule Kemoge_2_a: official
{
	meta:
		description = "This rule detects Kemoge aggresive Adware"
		sample = "_"
	strings:
		$a = {6C 61 73 74 53 65 6E 64 49 6E 73 74 61 6C 6C 65 64 50 61 63 6B 61 67 65 49 6E 66 6F 54 69 6D 65 3A}
		$b = {68 6F 75 72 41 66 74 65 72 4C 61 73 74 53 65 6E 64 3A}
		$c = {67 65 74 49 6E 73 74 61 6C 6C 65 64 50 61 63 6B 61 67 65 73 2E 6A 73 70}
		$d = {6B 65 6D 6F 67 65 2E 6E 65 74}
	condition:
		$a and $b and $c and $d
}


rule kemoge_b: signatures
{
	meta:
		description = "This rule detects kemoge adware using new approach for common code signature generation"
	strings:
	$S_12120 = { 12 ?? 39 ?? 08 00 22 ?? ?? ?? 70 10 ?? ?? ?? 00 27 ?? 6e 10 ?? ?? ?? 00 0c ?? 6e 10 ?? ?? ?? 00 0c 01 38 01 0f 00 6e 10 ?? ?? 01 00 0a ?? 33 ?? 09 00 62 ?? ?? ?? 6e 20 ?? ?? ?? 00 0c ?? 11 ?? 6e 10 ?? ?? ?? 00 0a ?? 32 ?? 16 00 6e 10 ?? ?? ?? 00 0c 00 38 00 10 00 6e 10 ?? ?? 00 00 0a ?? 33 ?? 0a 00 62 ?? ?? ?? 6e 20 ?? ?? ?? 00 0c ?? 28 e7 0d ?? 12 ?? 28 e4 }
	$S_3962 = { 39 04 08 00 22 ?? ?? ?? 70 10 ?? ?? ?? 00 27 ?? 12 f0 6e 10 ?? ?? 04 00 0c 01 6e 10 ?? ?? 04 00 0c 02 6e 10 ?? ?? 02 00 0c 02 12 03 6e 30 ?? ?? 21 03 0c 01 52 10 ?? ?? 0f 00 0d 01 28 fe }
	$S_6330 = { 63 00 ?? ?? 38 00 0c 00 12 ?? 60 01 ?? ?? 34 10 07 00 62 00 ?? ?? 71 ?? ?? ?? 20 ?? 0e 00 }
	$S_7120 = { 71 00 ?? ?? 00 00 62 00 ?? ?? 70 10 ?? ?? 00 00 0a 00 0f 00 }
	$S_6326 = { 63 00 ?? ?? 38 00 0a 00 12 ?? 60 01 ?? ?? 34 10 05 00 71 ?? ?? ?? 32 ?? 0e 00 }
	condition:
	3 of them		
}


rule KikDroid_a {
	strings:
		$s1 = "wss://arab-chat.site"
		$s2 = "wss://chat-messenger.site"
		$s3 = "wss://chat-world.site"
		$s4 = "wss://free-apps.us"
		$s5 = "wss://gserv.mobi"
		$s6 = "wss://kikstore.net"
		$s7 = "wss://network-lab.info"
		$s8 = "wss://onlineclub.info"
		$a1 = "/data/kik.android"
		$a2 = "spydroid"
	condition:
		1 of ($s*) and 1 of ($a*)
}


rule koler_a: example
{
	meta:
		description = "This rule detects koler rasomware"
		sample = "3c37588cece64fb3010ea92939a3873450dda70693f424d1f332b70677a96137 40cd3009c29f14046336627a9b6e61a1b88f375e2e6ff8d2743a197eb3e2c977"
	strings:
		$string_a = "These privileges are needed to protect your device from attackers, and will prevent Android OS from being destroyed."
		$string_b = "New-York1"
		$string_c = ".dnsbp.cloudns.pro"
	condition:
		( androguard.package_name("com.android.x5a807058") or
		androguard.activity(/x5a807058/i) or
		any of ($string_*) ) and
		androguard.permission(/com.android.browser.permission.READ_HISTORY_BOOKMARKS/)
}


rule koler_domains_a
{
	meta:
		description = "Old Koler.A domains examples"
		sample = "2e1ca3a9f46748e0e4aebdea1afe84f1015e3e7ce667a91e4cfabd0db8557cbf"
	condition:
		cuckoo.network.dns_lookup(/police-scan-mobile.com/) or
		cuckoo.network.dns_lookup(/police-secure-mobile.com/) or
		cuckoo.network.dns_lookup(/mobile-policeblock.com/) or
		cuckoo.network.dns_lookup(/police-strong-mobile.com/) or
		cuckoo.network.dns_lookup(/video-porno-gratuit.eu/) or
		cuckoo.network.dns_lookup(/video-sartex.us/) or 
		cuckoo.network.dns_lookup(/policemobile.biz/)
}
rule koler_builds_a
{
	meta:
		description = "Koler.A builds"
	strings:
		$0 = "buildid" wide ascii
		$a = "DCEF055EEE3F76CABB27B3BD7233F6E3" wide ascii
		$b = "C143D55D996634D1B761709372042474" wide ascii
	condition:
		$0 and ($a or $b)
}
rule koler_strings_a
{
	meta:
		description = "Koler strings"
	strings:
		$0 = "You device will be unprotectable. Are you sure?" wide ascii
	condition:
		1 of them
}
rule koler_class_a
{
	meta:
		description = "Koler.A class"
	strings:
		$0 = "FIND_VALID_DOMAIN" wide ascii
		$a = "6589y459" wide ascii
	condition:
		all of them
}
rule koler_D_a
{
	meta:
		description = "Koler.D class"
	strings:
		$0 = "ZActivity" wide ascii
		$a = "Lcom/android/zics/ZRuntimeInterface" wide ascii
	condition:
		all of them
}


rule koler_b: ransomware
{
	meta:
		description = "This rule detects koler ransomware, experimental approach based on common methods and signature creation"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
	$a = {12 00 5c 10 ?? ?? 12 02 6f 20 ?? ?? 31 00 0e 00}
	$b = {55 10 ?? ?? 39 00 0f 00 38 03 0d 00 12 10 5c 10 ?? ?? 59 12 ?? ?? 5c 14 ?? ?? 6f 30 ?? 00 21 03 0e 00 52 10 ?? ?? 32 20 fd ff 3d 02 fb ff 38 03 f9 ff 59 12 ?? ?? 1a 00 ?? ?? 6e 20 ?? ?? 01 00 0c 00 1f 00 ?? 00 6e 30 ?? 00 20 03 28 ea}
	$c = {12 f1 22 00 ?? 00 13 03 da 07 13 04 00 01 12 d5 01 12 76 06 ?? ?? 00 00 5b 60 ?? 00 54 60 ?? 00 6e 10 ?? ?? 06 00 0a 01 59 01 ?? 00 6e 10 ?? ?? 06 00 0e 00 }
	$d = {6f 10 ?? ?? 01 00 5b 11 ?? 00 22 00 ?? 00 70 20 ?? ?? 10 00 5b 10 ?? 00 0e 00 }
	$e = {70 10 ?? ?? 02 00 6e 10 ?? ?? 02 00 0c 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 1f 00 ?? ?? 54 21 ?? ?? 72 30 ?? ?? 20 01 13 00 08 00 6f 20 ?? ?? 02 00 0e 00 }
	$f = {6e 10 ?? ?? 01 00 0a 00 39 00 08 00 13 00 08 00 6e 20 ?? ?? 01 00 0e 00 12 00 6e 20 ?? ?? 01 00 6e 10 ?? ?? 01 00 28 f8 }
	$g = {6e 10 ?? ?? 02 00 0a 00 38 00 1f 00 6e 10 ?? ?? 02 00 70 10 ?? ?? 02 00 6e 10 ?? ?? 02 00 6e 10 ?? ?? 02 00 0c 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 1f 00 ?? ?? 54 21 ?? ?? 72 30 ?? ?? 20 01 6e 10 ?? ?? 02 00 0e 00 }
	$h = {12 11 12 00 39 06 23 00 6e 10 ?? ?? 05 00 0c 02 52 53 ?? ?? 6e 10 ?? ?? 05 00 0a 04 38 04 15 00 6e 30 ?? ?? 32 00 6e 10 ?? ?? 05 00 0a 00 32 60 0b 00 6e 20 ?? ?? 65 00 0a 00 38 00 05 00 6f 20 ?? ?? 65 00 0e 00 01 10 28 ec 6e 10 ?? ?? 05 00 0c 02 52 53 ?? ?? 6e 10 ?? ?? 05 00 0a 04 38 04 06 00 6e 30 ?? ?? 32 00 28 df 01 10 28 fb }
	$i = {12 11 70 20 ?? 00 32 00 12 00 59 20 ?? 00 14 00 01 00 03 7f 59 20 ?? 00 59 21 ?? 00 6e 20 ?? ?? 12 00 6e 10 ?? ?? 02 00 0e 00 }
	condition:
	6 of them	
}


rule leadbolt_a: advertising
{
	meta:
		description = "Leadbolt"
	condition:
		androguard.url(/http:\/\/ad.leadbolt.net/)
}


rule LeakerLocker_a
{
	meta:
		description = "This rule detects Leaker Locker samples"
		sample = "8a72124709dd0cd555f01effcbb42078"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/leakerlocker-mobile-ransomware-acts-without-encryption/"
	condition:
		androguard.receiver(/receiver.LockScreenReceiver/)
}


rule libyan_scorpions_a
{
	meta:
		source = "https://cyberkov.com/wp-content/uploads/2016/09/Hunting-Libyan-Scorpions-EN.pdf"
		sample = "e66d795d0c832ad16381d433a13a2cb57ab097d90e9c73a1178a95132b1c0f70"
		dropped = "4e656834a93ce9c3df40fe9a3ee1efcccc728e7ea997dc2526b216b8fd21cbf6"
	strings:
		$ip_1 = "41.208.110.46" ascii wide
		$domain_1 = "winmeif.myq-see.com" ascii wide nocase
		$domain_2 = "wininit.myq-see.com" ascii wide nocase
		$domain_3 = "samsung.ddns.me" ascii wide nocase
		$domain_4 = "collge.myq-see.com" ascii wide nocase
		$domain_5 = "sara2011.no-ip.biz" ascii wide nocase
	condition:
		androguard.url(/41\.208\.110\.46/) or cuckoo.network.http_request(/41\.208\.110\.46/) or
		androguard.url(/winmeif.myq-see.com/i) or cuckoo.network.dns_lookup(/winmeif.myq-see.com/i) or
		androguard.url(/wininit.myq-see.com/i) or cuckoo.network.dns_lookup(/wininit.myq-see.com/i) or
		androguard.url(/samsung.ddns.me/i) or cuckoo.network.dns_lookup(/samsung.ddns.me/i) or
		androguard.url(/collge.myq-see.com/i) or cuckoo.network.dns_lookup(/collge.myq-see.com/i) or
		androguard.url(/sara2011.no-ip.biz/i) or cuckoo.network.dns_lookup(/sara2011.no-ip.biz/i) or
		any of ($domain_*) or any of ($ip_*) or
		androguard.certificate.sha1("DFFDD3C42FA06BCEA9D65B8A2E980851383BD1E3")
}


rule lipizzan_1_a
{
	meta:
		description = "Detects Lipizzan related samples"
		md5 = "6732c7124f6f995e3736b19b68518e77"
		blog = "https://nakedsecurity.sophos.com/2017/07/28/lipizzan-spyware-linked-to-cyberarms-firm-plunders-sms-logs-and-photos/"
	strings:
		$a_1 = "KILL"
		$a_2 = "SNAPSHOT"
		$a_3 = "SCREENSHOT"
		$a_4 = "VOICE"
		$a_5 = "USER_FILE"
		$a_6 = "CONFIGURATION"
	condition:
		all of ($a_*)
}


rule LLCdev_a: official
{
	meta:
		description = "This rule detects samples fom LLC developer"
		sample = "00d0dd7077feb4fea623bed97bb54238f2cd836314a8900f40d342ccf83f7c84"
	condition:
		androguard.certificate.sha1("D7FE504792CD5F67A7AF9F26C771F990CA0CB036")
}


rule Locker_a: official
{
	meta:
		description = "This rule detects one variant of Locker malware"
		sample = "039668437547FE920F15C972AE8EB94F063C75409FB78D8D8C8930BD3B07DFFC"
	strings:
		$a = {64 65 6C 65 74 65 41 50 50}
		$b = {6C 6C 5F 63 6F 64 65 69 6E 70 75 74}
		$c = {6C 6C 5F 73 75 63 63 73 65 73 73}
		$d = {44 45 56 49 43 45 5F 41 44 4D 49 4E}
	condition:
		$a and $b and $c and $d
}


rule locker_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "45b74b69378429e7670e50e3e4d502baf701cf33fbbf341125b998dc8c316369"
		sample2 = "76187efe8a59128b5becb4f13812b846edda58e270579b6938269ce24d2b2e9b"
		sample3 = "50f39306f85f4f26c272c46068bdc995fec3433d7671fdb68506e5777c983043"
		sample4 = "f467d7e0c0fc8b5a02859ab40545205baf92919fa391a24fc38b4ccb54d919ed"
	strings:
		$a = "4Landroid/hardware/camera2/CameraCharacteristics$Key;"
		$b = "yYE-[xX>i"
		$c = "/You device will be unprotectable. Are you sure?"
		$d = "8android.app.action.ACTION_DEVICE_ADMIN_DISABLE_REQUESTED"
	condition:
		all of them
}


rule Ransom_b:Cokri {
	meta:
	description = "Trojan Locker Cokri"
	strings:
	$ = "com/example/angrybirds_test/MyService" 
	$ = "world4rus.com"
	$ = "api.php/?devise"
	condition:
	all of them
}


rule lockerpin_a
{
	meta:
		description = "This rule detects LockerPin apps"
		sample = "2440497f69ec5978b03ea5eaf53a63f5218439a6e85675811c990aa7104d6f72"
		sample2 = "99366d0bd705e411098fade5a221a70863038f61344a9f75f823c305aa165fb1"
		sample3 = "ca6ec46ee9435a4745fd3a03267f051dc64540dd348f127bb33e9675dadd3d52"
	strings:
		$a = "res/drawable-hdpi-v4/fbi.png"
		$b = "<b>IMEI:</b>"
		$c = "res/drawable-xhdpi-v4/hitler_inactive.png"
		$d = "res/drawable-xhdpi-v4/gov_active.pngPK"
	condition:
		all of them
}


rule locker_b: ccm
{
	meta:
		description = "This rule detects pornlocker for ccm"
		sample = "e09849761ab3e41e9b88fe6820c0b536af4dbbb016a75248b083c25ce3736592"
	strings:
		$S_16_7160 = { 71 10 ?? ?? 04 00 0a 00 39 00 0b 00 60 00 02 00 13 01 13 00 34 10 06 00 71 30 ?? ?? 42 03 0e 00 60 00 02 00 13 01 0e 00 34 10 06 00 71 30 ?? ?? 42 03 28 f6 71 20 ?? ?? 42 00 28 f2 }
		$S_128_2820 = { 28 06 22 00 ?? 00 70 10 ?? ?? 00 00 ?? ?? ?? ?? ?? ?? 0e 00 }
		$S_16_6230 = { 62 00 ?? 00 71 20 ?? ?? 01 00 0c 00 71 10 ?? ?? 00 00 71 20 ?? ?? 02 00 0e 00 0d 00 28 fe }
		$S_714_2822 = { 28 06 22 01 ?? 00 70 10 ?? ?? 01 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 }
		$S_32_1298 = { 12 04 71 20 ?? ?? 65 00 0c 00 71 20 ?? ?? 50 00 0c 00 1f 00 ?? ?? 1f 00 ?? ?? 71 10 ?? ?? 00 00 0c 01 71 10 ?? ?? 01 00 0c 01 21 02 21 73 b0 32 71 20 ?? ?? 21 00 0c 01 1f 01 ?? ?? 1f 01 ?? ?? 21 02 21 73 71 53 ?? ?? 47 21 21 02 71 52 ?? ?? 40 41 71 20 ?? ?? 65 00 0c 00 71 30 ?? ?? 50 01 0e 00 }
	condition:
		all of them
}


rule Locker_K_a
{
	meta:
		description = "This rulset detects the Android Screen Locker"
		date = "06-July-2016"
		sample = "e8c9bc0f37395572a6ad43a4f1e11f8eeb86b6f471f443714f6fb1bcb465e685"
	strings:
		$a = "<br>Do not turn off or reboot your phone during update"
	condition:
		androguard.filter(/DEVICE_ADMIN_ENABLED/) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and $a
}


rule lokibot_old_a
{
    strings:
		$a1 = "Seller" 
		$a2 = "Domian1" 
	condition:
        androguard.package_name(/compse.refact.st.upsssss/) and 
		1 of ($a*)
}


rule loki_skd_a
{
	meta:
	description = "This rule detects com.loki.sdk"
	strings:
		$a = "com/loki/sdk/"
		$b = "com.loki.sdk.ClientService"
	condition:
		$a or $b
}


rule londatiga_a
{
	condition:
		androguard.certificate.sha1("ECE521E38C5E9CBEA53503EAEF1A6DDD204583FA")
}


rule lop_K_a
{
	meta:
		description = "This rule detects the lop files"
		sample = "f8537cc4bc06be5dd47cdee422c3128645d01a2536f6fd54d2d8243714b41bdd"
	strings:
		$a = "assets/daemon"
		$b = "assets/exp"
	condition:
		$a and $b
}


rule LotsofAds_a
{
	meta:
		description = "This rule detects apps with lots of ads"
	strings:
        $aa = "com.vungle.publisher.FullScreenAdActivity"
		$ab = "com.inmobi.rendering.InMobiAdActivity"
		$ac = "com.amazon.device.ads.AdActivity"
		$ad = "com.yandex.mobile.ads.AdActivity"
		$ae = "com.mopub.common.MoPubBrowser"
		$af = "com.facebook.ads.InterstitialAdActivity"
		$ag = "com.unity3d.ads.android.view.UnityAdsFullscreenActivity"
		$ai = "com.google.android.gms.ads.AdActivity"
		$aj = "com.startapp.android.publish.AppWallActivity"
		$ak = "com.jirbo.adcolony.AdColonyFullscreen"
		$al = "com.unity3d.ads.android2.view.UnityAdsFullscreenActivity"
		$an = "com.startapp.android.publish.FullScreenActivity"
		$ao = "com.jirbo.adcolony.AdColonyOverlay"
		$ap = "org.nexage.sourcekit.mraid.MRAIDBrowser"
		$aq = "com.appodeal.ads.networks.vpaid.VPAIDActivity"
		$as = "com.appodeal.ads.InterstitialActivity"
		$at = "com.startapp.android.publish.list3d.List3DActivity"
		$au = "com.appodeal.ads.VideoActivity"
		$av = "org.nexage.sourcekit.vast.activity.VPAIDActivity"
		$aw = "com.appodeal.ads.networks.SpotXActivity"
		$ax = "org.nexage.sourcekit.vast.activity.VASTActivity"
		$az = "com.startapp.android.publish.OverlayActivity"
		$ba = "com.appodeal.ads.LoaderActivity"
		$bc = "ru.mail.android.mytarget.ads.MyTargetActivity"
		$bd = "com.flurry.android.FlurryFullscreenTakeoverActivity"
		$be = "com.google.android.gms.ads.purchase.InAppPurchaseActivity"
		$bfa = "com.jirbo.adcolony.AdColonyBrowser"
		$bha = "com.mopub.mobileads.MoPubActivity"
		$bia = "com.applovin.adview.AppLovinInterstitialActivity"
		$bja = "com.mopub.mobileads.MraidVideoPlayerActivity"
		$bka = "com.mopub.mobileads.MraidActivity"
condition:
		20 of them
}


rule malicious_certs_a
{
	condition:
		androguard.certificate.sha1("437423567AA682723D3ADD8BAD316BD578F2EB85") or
		androguard.certificate.sha1("9BB11D691804256616B232C1D803ADC3CDFF4B6D") or
		androguard.certificate.sha1("D5274E3BF8B2F0B6E3D69ECF064D38CD74B3E64B") or
		androguard.certificate.sha1("0ECA59048B29A69FC7F9655C0534EB97BFF15893") or
		androguard.certificate.sha1("8B373E842398325296B6FDC302296AD1F6CFCEDA")
		or androguard.certificate.sha1("1B1DE0EF592C729D2BC578A259F6D740FE3E1C4E")
		or androguard.certificate.sha1("1D4A315F36C933028F1938979354D68F69217993")
		or androguard.certificate.sha1("046BF157D644F2DE7BF0BCEC8C5D4E240C9F1901")
		or androguard.certificate.sha1("9465535F221311ECDE7CB0886930E639AA4A47C2")
		or androguard.certificate.sha1("F55C09CF87F998364C5B679E8219475FDB708F56")
		or androguard.certificate.sha1("19E98203E736DE818F79A8BC9541D8BF6A0EC7DE")
		or androguard.certificate.sha1("34E39C32B5561EC307FB133ABA3C637A99D62E3A")
		or androguard.certificate.sha1("A66802E44869280D14FECE10661370D6AA13F79E")
		or androguard.certificate.sha1("69DA14E583BF3127015ADD077B997DB1474A5312")
		or androguard.certificate.sha1("97C962C8AC89663B9041CC0E08057200A65560F2")
		or androguard.certificate.sha1("A1480C8895A8B10A34C714867FFFD3CF98A5C8B5")
		or androguard.certificate.sha1("34E39C32B5561EC307FB133ABA3C637A99D62E3A")
		or androguard.certificate.sha1("3B2097D66D27A248B8F45332A52F7B83DC98F2D3")
		or androguard.certificate.sha1("623CFF4004DB8D106FB47EDD20A53138892CD7DD")
		or androguard.certificate.sha1("EED7DF45045A39EC7D11991CE983DFC50D91ACF7")
		or androguard.certificate.sha1("6668C30E3C4DB3FD68C1EC79DA3468457B2B3028")
}


rule malicious_cert_a
{
	meta:
		description = "This rule detects apps with malicious certs"
		sample = "a316a8cccbee940c3f0003344e6e29db163b1c82cd688bdc255a69300470124c"
	condition:
		androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB")
}


rule Malicious_iFrame_a
{
	meta:
		description = "This rule detectes apps with hidden malicious iframe"
		sample = "d6289fa1384fab121e730b1dce671f404950e4f930d636ae66ded0d8eb751678"
	strings:
		$e = "Brenz.pl"
		$a = "iframe style=\"height:1px"
		$b = "frameborder=0 width=1></iframe"
	condition:
		($e and androguard.certificate.sha1("69CE857378306A329D1DCC83A118BC1711ABA352")) or
		($a and $b and $e)
}


rule test2_a
{
	meta:
		description = "This rule detects apps with VirusService"
		sample = "5C0A65D3AE9F45C9829FDF216C6E7A75AD33627A"
	condition:
		androguard.service(/\.VirusService/i)
}


rule certs_a
{
	condition:
		androguard.certificate.sha1("3F65615D7151BA782F9C0938B01F4834B8E492BC") or
		androguard.certificate.sha1("AFD2E81E03F509B7898BFC3C2C496C6B98715C58") or
		androguard.certificate.sha1("E6D2E5D8CCBB5550E666756C804CA7F19A523523") or
		androguard.certificate.sha1("7C9331A5FE26D7B2B74C4FB1ECDAF570EFBD163C")          // Ransomware Locker
}


rule malware_P4_a
{
	meta:
		description = "malware_P4"
	strings:
		$a = "http://185.62.188.32/app/remote/"
		$b = "intercept_sms"
		$c = "unblock_all_numbers"
		$d = "unblock_numbers"
		$e = "TYPE_INTERCEPTED_INCOMING_SMS"
		$f = "TYPE_LISTENED_INCOMING_SMS"
	condition:
		$a and $b and ($c or $d or $e or $f)
}


rule Mapin_a:trojan
{
	meta:
		description = "Mapin trojan, not droppers"
		sample = "7f208d0acee62712f3fa04b0c2744c671b3a49781959aaf6f72c2c6672d53776"
	strings:
		$a = "138675150963" //GCM id
		$b = "res/xml/device_admin.xml"
		$c = "Device registered: regId ="
	condition:
		all of them
}


rule dropperMapin_a
{
	meta:
		description = "This rule detects mapin dropper files"
		sample = "7e97b234a5f169e41a2d6d35fadc786f26d35d7ca60ab646fff947a294138768"
		sample2 = "bfd13f624446a2ce8dec9006a16ae2737effbc4e79249fd3d8ea2dc1ec809f1a"
	strings:
		$a = ":Write APK file (from txt in assets) to SDCard sucessfully!"
		$b = "4Write APK (from Txt in assets) file to SDCard  Fail!"
		$c = "device_admin"
	condition:
		all of them
}


rule MapinDropper_a
{
	meta:
		description = "This rule detects mapin dropper files"
		sample = "745e9a47febb444c42fb0561c3cea794"
	strings:
		$a = "assets/systemdataPK"
		$b = "assets/systemdata"
		$e = "assets/resourcea"
		$f = "assets/resourceaPK"
	condition:
		$a or $b or $e or $f
}


rule Android_Marcher_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "04-July-2016"
		description = "Marcher has been active since 2013; like any commercial malware, it is featured in different campaigns, in multiple countries."
		source = "https://exchange.xforce.ibmcloud.com/collection/Marcher-Android-Bot-eeede463ee5c2b57402fc86154411e65"
	condition:
		(androguard.filter(/com.KHLCert.fdservice/i) and
		androguard.filter(/com.KHLCert.gpservice/i))
}


rule marcher_b
{
	meta:
		description = "This rule detects Sicherheits-App Banker Trojans, also known as Marcher"
		sample = "8994b4e76ced51d34ce66f60a9a0f5bec81abbcd0e795cb05483e8ae401c6cf7"
	condition:
		androguard.package_name(/[a-z]+\.[a-z]+/) and
		androguard.app_name(/.*Sicherheits[- ]App$/) and
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")
}


rule Marcher_a: Targeting German Banks
{
	meta:
        description = "Trojan 'Marcher' targeting German Banks"
	strings:
		$target1 = ".starfinanz." nocase
		$target2 = ".fiducia." nocase
		$target3 = ".dkb." nocase
		$target4 = ".postbank." nocase
		$target5 = ".dkbpushtan" nocase
		$configC2 = "%API_URL%%PARAM%" nocase
	condition:
		1 of ($target*) 
		and $configC2 
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}


rule marcher_v2_a
{
	meta:
		description = "This rule detects a new variant of Marcher"
		sample = "27c3b0aaa2be02b4ee2bfb5b26b2b90dbefa020b9accc360232e0288ac34767f"
		author = "Antonio S. <asanchez@koodous.com>"
	strings:
		$a = /assets\/[a-z]{1,12}.datPK/
		$b = "mastercard_img"
		$c = "visa_verifed"
	condition:
		all of them
}


rule Marcher_new_a
{
	meta:
		description = "This rule detects new Marcher variant with device admin notification screen"
		sample = "b956e12475f9cd749ef3af7f36cab8b20c5c3ae25a13fa0f4927963da9b9256f"
	strings:
		$a = "res/xml/device_admin_new.xml"
	condition:
		$a
}


rule Marcher_ObfuscatedStr_a
{
	meta:
		description = "This rule detects hardcoded strings in marcher malware using regex built to detect their string obfuscation scheme. Strings are obfuscated with each character being delimited by (** or <<) 3 random chars (** or >>) and these characters vary for each apk"
		sample = "8e9bdb1f5a37471f3f50cc9d482ea63c377e84b73d9bae6d4f37ffe403b9924e"
	strings:
		$a = /A(\*{2}|<{2})\w{3}(\*{2}|>{2})c(\*{2}|<{2})\w{3}(\*{2}|>{2})c(\*{2}|<{2})\w{3}(\*{2}|>{2})o(\*{2}|<{2})\w{3}(\*{2}|>{2})u(\*{2}|<{2})\w{3}(\*{2}|>{2})n(\*{2}|<{2})\w{3}(\*{2}|>{2})t/
		$b = /C(\*{2}|<{2})\w{3}(\*{2}|>{2})a(\*{2}|<{2})\w{3}(\*{2}|>{2})r(\*{2}|<{2})\w{3}(\*{2}|>{2})d/
		$c = /C(\*{2}|<{2})\w{3}(\*{2}|>{2})o(\*{2}|<{2})\w{3}(\*{2}|>{2})n(\*{2}|<{2})\w{3}(\*{2}|>{2})n(\*{2}|<{2})\w{3}(\*{2}|>{2})e(\*{2}|<{2})\w{3}(\*{2}|>{2})c(\*{2}|<{2})\w{3}(\*{2}|>{2})t/
	condition:
		$a or
		$b or
		$c
}


rule Marcher_b: more obfuscated versions
{
	meta:
		description = "This rule detects more obfuscated versions of marcher - 2017-04-27"
		sample = "e5ee5285b004faf53fca9b7c5e2c74316275413ef92f3bcd3a457c9b81a1c13e"
	strings:
		$string_1 = "gp_dialog_password" nocase
		$string_2 = "Visa password" nocase
		$string_3 = "Amex SafeKey password" nocase
		$string_4 = "Secure Code Password" nocase
	condition:
		2 of ($string_*)
		and androguard.permission(/android.permission.RECEIVE_SMS/)
		and androguard.permission(/android.permission.GET_TASKS/)
		and androguard.filter(/.*DEVICE_ADMIN_ENABLED.*/)
}
rule Marcher2_a: more obfuscated versions
{
	meta:
		description = "This rule detects more obfuscated versions of marcher - 2017-06-08"
		sample = "a61e97e4b1fa49560dd6d08e2a135b0bf6c27550953671d56ca37b95f017b19d"
	strings:
		$string_gp = "gp_dialog_password" nocase
		$string_cc_1 = "amex_verified" nocase
		$string_cc_2 = "mastercard_verified" nocase
		$string_cc_3 = "visa_verified" nocase
	condition:
		$string_gp
		and 1 of ($string_cc_*)
		and androguard.permission(/android.permission.RECEIVE_SMS/)
		and androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)
		and androguard.filter(/.*DEVICE_ADMIN_ENABLED.*/)
}


rule Mazain_a: Banker
{
	meta:
		description = "This rule detects Mazain banker"
		sample = "9f3965042c5521ce1eba68f417e9be91cb0050cd8ed5f054a7ad60afc8a4e111"
		author = "A.Sanchez <asanchez@koodous.com>"
	strings:
		$ = "goo.gl/fDqpmZ"
		$ = "22222.mcdir.ru"
		$ = "111111111.mcdir.ru"
		$ = "a193698.mcdir.ru"
		$ = "firta.myjino.ru"
		$ = "ranito.myjino.ru"
		$ = "kinoprofi.hhos.ru"
		$ = "cclen25sm.mcdir.ru"
		$ = "321123.mcdir.ru"
		$ = "000001.mcdir.ru"
		$ = "104.238.176.73"
		$ = "probaand.mcdir.ru"
		$ = "jekobtrast1t.ru"
		$ = "dronnproto.temp.swtest.ru"
		$ = "videoboxonline.com"
		$ = "onlinevtvideos.com"
		$ = "clen1.mcdir.ru"
		$ = "xowarm.ru"
		$ = "foxmix.mcdir.ru"
		$ = "130.0.233.109"
		$ = "spankedteens.pw"
		$ = "46.183.216.173"
		$ = "srv114389.hoster-test.ru"
	condition:
		1 of them
		or androguard.package_name("com.example.livemusay.myapplication")
		or androguard.package_name("kris.myapplication")
		or androguard.package_name("com.bagirase.livemusay.hrre")
}
rule Mazain_strings_a: Banker
{
	meta:
		description = "This rule detects Mazain malware based on strings"
		sample = "f4672da546b51b2978e10ff97fbc327665fb2c46ea96cea3e751b33b044b935d"
	strings:
		$required_1 = "activity_inj"
		$required_2 = "activity_go_adm"
		$required_3= "activity_activ_location"
		$opt_1 = "$$res/mipmap-xxhdpi-v4/ic_launcher.png"
		$opt_2 = "android.intent.action.NEW_OUTGOING_CALL"
		$opt_3 = "com.example.livemusay.myapplication"
		$opt_4 = "android.intent.action.QUICKBOOT_POWERON"
		$opt_5 = "android.permission.QUICKBOOT_POWERON"
		$opt_6 = "res/layout/activity_inj.xml"
		$opt_7 = "res/layout/activity_go_adm.xml"
		$opt_8 = "res/layout/r_l.xml"
		$opt_9 = "encrypted-storage"
		$opt_10 = "android.app.action.DEVICE_ADMIN_DISABLED"
	condition:
		all of ($required_*) and 2 of ($opt_*)
}


rule Android_MazarBot_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects MazarBot"
		source = "https://heimdalsecurity.com/blog/security-alert-new-android-malware-post-denmark/"
	condition:
		(androguard.filter(/wakeup/i) and 
		 androguard.filter(/reportsent/i)) or
		(androguard.filter(/wakeup/i) and 
		 androguard.filter(/com\.whats\.process/i))
}


rule metasploit_a
{
	meta:
		description = "This rule detects apps made with metasploit framework"
		sample = "cb9a217032620c63b85a58dde0f9493f69e4bda1e12b180047407c15ee491b41"
	strings:
		$a = "*Lcom/metasploit/stage/PayloadTrustManager;"
		$b = "(com.metasploit.stage.PayloadTrustManager"
		$c = "Lcom/metasploit/stage/Payload$1;"
		$d = "Lcom/metasploit/stage/Payload;"
	condition:
		all of them
}
rule metasploit_obsfuscated_a
{
	meta:
		description = "This rule tries to detect apps made with metasploit framework but with the paths changed"
	strings:
		$a = "currentDir"
		$b = "path"
		$c = "timeouts"
		$d = "sessionExpiry"
		$e = "commTimeout"
		$f = "retryTotal"
		$g = "retryWait"
		$h = "payloadStart"
		$i = "readAndRunStage"
		$j = "runStageFromHTTP"
		$k = "useFor"
	condition:
		all of them
}


rule android_metasploit_a: android
{
	meta:
	  author = "https://twitter.com/plutec_net"
	  description = "This rule detects apps made with metasploit framework"
	strings:
	  $a = "*Lcom/metasploit/stage/PayloadTrustManager;"
	  $b = "(com.metasploit.stage.PayloadTrustManager"
	  $c = "Lcom/metasploit/stage/Payload$1;"
	  $d = "Lcom/metasploit/stage/Payload;"
	condition:
	  $a or $b or $c or $d
}


rule Metasploit_Payload_a
{
  meta:
      author = "https://www.twitter.com/SadFud75"
      information = "Detection of payloads generated with metasploit"
  strings:
      $s1 = "-com.metasploit.meterpreter.AndroidMeterpreter"
      $s2 = ",Lcom/metasploit/stage/MainBroadcastReceiver;"
      $s3 = "#Lcom/metasploit/stage/MainActivity;"
      $s4 = "Lcom/metasploit/stage/Payload;"
      $s5 = "Lcom/metasploit/stage/a;"
      $s6 = "Lcom/metasploit/stage/c;"
      $s7 = "Lcom/metasploit/stage/b;"
  condition:
      androguard.package_name("com.metasploit.stage") or any of them
}


rule MilkyDoor_a {
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/operation-c-major-actors-also-used-android-blackberry-mobile-spyware-targets/"
	strings:
	  	$ = /144.76.108.61/
		$ = /hgnhpmcpdrjydxk.com/
		$ = /jycbanuamfpezxw.com/
		$ = /liketolife.com/
		$ = /milkyapps.net/
		$ = /soaxfqxgronkhhs.com/
		$ = /uufzvewbnconiyi.com/
		$ = /zywepgogksilfmc.com/
	condition:
		1 of them
}


rule mkero_a
{
	meta:
		description = "This rule detects MKero malware family"
		sample = "a1e71e8b4f8775818db65655fb3e28666f7b19fd798360297c04cfe5c9a6b87e"
		sample2 = "136ba8af7c02e260db53817a142c86b65775510295720a2ec339e70cbbebf2d4"
		source = "http://www.hotforsecurity.com/blog/sophisticated-capcha-bypassing-malware-found-in-google-play-according-to-bitdefender-researchers-12616.html"
	strings:
		$a = "com/mk/lib/receivers/MkStart"
		$b = "com/mk/lib/MkOpen"
		$c = "com/mk/lib/MkProcess"
		$d = "com/mk/lib/MkServer"
		$e = "com/mk/lib/MkSource"
		$f = "com/mk/lib/MkPages"
		$g = "com/mk/lib/receivers/MkSms"
	condition:
		all of them
}
rule mkero_cert_a
{
	condition:
		androguard.certificate.sha1("49A6EFC6A9BA3DE7ECB265E7B4C43E454ABDA05D")
}


rule appaction_a
{
	meta:
		description = "Gets the user to send MMS and SMS to remote host with info"
	strings:
		$a = "com.hzpz.pay.game.SEND_SMS1_SUC"
		$b = "com.hzpz.pay.game.ACTION_MMS1_RECIVE"
	condition:
		all of them
}
rule remotehost_a
{
	strings:
		$a = "http://221.12.6.198:8010/APP/GetFeePoint.aspx"
		$b = "http://221.12.6.198:8010/APP/AppPaylog.aspx"
		$c = "http://221.12.6.198:8010/APP/AppPayResultLog.aspx"
		$d = "http://221.12.6.198:8010/WoRead/GetOrder.aspx?AppId=2&MyOrderId="
		$e = "http://221.12.6.198:8010/CMRead/GetOrder.aspx?MyOrderId="
		$f = "http://61.130.247.175:8080/portalapi/enable/getMdnFromIMSI?IMSI="
		$g = "http://211.136.165.53/wap/mh/p/sy/kj/cz/index.jsp"
	condition:
			any of them 
}


/*
this is used to filter one of the MMVideo by its pay configuaration
public static final String BY_URL = "baiy/pay/wxScan";
public static final int EXCUTE_AGAIN = 400;
public static final String GZH_URL = "content/savePayInfo";
public static final String RONGHE_WAP = "http://pay.fzw988.com/apiTvShow/itf/getallurlbyname?name=scanandzfb";
public static final String SCAN_JUMP = "pages/paySuccess.jsp";
public static final String SCAN_QUERY = "content/commquery";
public static final String SCAN_REQUEST = "citicscan/wxscanUrl";
public static final String SCAN_REQUEST3 = "citicscan/wxscanUrl3";
public static final String SFT_NOTIFY = "ytwx/notify";
public static final String SFT_URL = "ytwx/wapPay";
public static final String TY_WXWAP_URL = "qixun/wxH5Pay";
public static final String URL_SELF = "citic/ali/scan";
public static final String XC_URL = "xiaoc/gwapPay";
public static final String XYT_URL = "xyt/gwappay";
public static final String ZX_URL = "zhongx/pay";
public static int requestOk;
static {
PayConfig.contact = "13120747542/2818147339";
PayConfig.prefixUrl = "http://pay.epgaclub.com/apiTvShow/";
PayConfig.gzhStart = "http://12.3.js.cn/tvr725.php";
PayConfig.selfWx = 0;
rule MMVideo_Pay_1_a: MMVideo
{
	meta:
		description = "this is used to filter one of the MMVideo by its pay configuaration"
	strings:
		$paycfg_0 = "baiy/pay/wxScan"
		$paycfg_1 = "content/savePayInfo"
		$paycfg_2 = "http://pay.fzw988.com/apiTvShow/itf/getallurlbyname?name=scanandzfb"
		$paycfg_3 = "pages/paySuccess.jsp"
		$paycfg_4 = "content/commquery"
		$paycfg_5 = "citicscan/wxscanUrl"
		$paycfg_6 = "citicscan/wxscanUrl3"
		$paycfg_7 = "ytwx/notify"
		$paycfg_8 = "ytwx/wapPay"
		$paycfg_9 = "qixun/wxH5Pay"
		$paycfg_10 = "citic/ali/scan"
		$paycfg_11 = "xiaoc/gwapPay"
		$paycfg_12 = "xyt/gwappay"
		$paycfg_13 = "zhongx/pay"
		$paycfg_14 = "13120747542/2818147339"
		$paycfg_15 = "http://pay.epgaclub.com/apiTvShow/"
		$paycfg_16 = "http://12.3.js.cn/tvr725.php"
	condition:
		any of them
}


rule mobidash_a: advertising
{
	meta:
		description = "This rule detects MobiDash advertising"
		sample = "c77eed5e646b248079507973b2afcf866234001166f6d280870e624932368529"
	strings:
		$a = "res/raw/ads_settings.json"
		$b = "IDATx"
	condition:
		($a or $b) and androguard.activity(/mobi.dash.*/)
}


rule MobiDash_a
{
	meta:
		description = "MobiDash Adware evidences"
	strings:
		$a = "mobi_dash_admin" wide ascii
		$b = "mobi_dash_account_preferences.xml" wide ascii
	condition:
		all of them
}
rule MobiDash_v3_a
{
	meta:
		description = "MobiDash Adware evidences v3"
		sample = "6c2ffbede971283c7ce954ecf0af2c5ea5a5d028d3d013d37c36de06e9e972f3"
	strings:
		$1 = "Lmobi/dash/api/BannerRequest" wide ascii
		$2 = "mobi.dash.sdk.AdmobActivity" wide ascii
	condition:
		1 of them
}


rule koodous_s: official
{
	meta:
		description = "mono - network"
	condition:
		androguard.service(/ir.mono/i) or
		androguard.url(/api.\mono\.ir/)
}


rule mopub_a
{
	meta:
		description = "This rule detects aggressive (fake) mopub adware"
		sample = "aad96bdaad938b4ddb6b7ceb11311a99f21a2d4351566efc8ca075b52d9bc6b1"
		author = "https://twitter.com/agucova"
	strings:
		$number = ";njASk3`"
		$wstring = ";38p`_w&"
		$anotherstring = "/7#,v\"<s"
		$evenanother = "q;KAzzz-"
	condition:
		androguard.certificate.sha1("41653FD4CBC306FEF0DD26D68D1AB416285568C8") or
		androguard.package_name("com.mopub") or
		($number and $wstring and $anotherstring and $evenanother)
}


rule moscow_fake_a: banker
{
	meta:
		description = "Moskow Droid Development"
		thread_level = 3
		in_the_wild = true
	strings:
		$string_a = "%ioperator%"
		$string_b = "%imodel%"
		$string_c = "%ideviceid%"
		$string_d = "%ipackname%"
		$string_e = "VILLLLLL"
	condition:
		all of ($string_*)
}


rule Mulad_a
{
	meta:
        description = "Evidences of Mulad Adware via rixallab component"
	strings:
		$1 = "Lcom/rixallab/ads/" wide ascii
   	condition:
    	$1 or androguard.service(/com\.rixallab\.ads\./)
}


rule POB_1_a
{
	meta:
		description = "Detects few MyPleasure app"
	condition:
		(androguard.service(/ch.nth.android.contentabo.service.DownloadAppService/))
}


rule Root_zk_a: NetTraffic
{
	meta:
		description = "This rule detects root related about zookxxxxxx "
		sample = "fa48660370dc236ad80b5192fb1992d53f8d6e2cd8b2aa04ba9e9b3856aa9d96"
		detail = ""
	strings:
		$str_Matrix_0 = "/MatrixClient;"
		$str_Matrix_1 = "getLogTag"
		$str_Config_0 = "META-INF/SCONFIG"
	condition:
		all of ($str_Matrix_*) or
		any of ($str_Config_*) or
		cuckoo.network.dns_lookup(/m\.fruitnotlike\.com/) or
		cuckoo.network.dns_lookup(/n\.dingda585\.com/) or
		cuckoo.network.dns_lookup(/p\.bringbiggame\.com/) or
		cuckoo.network.dns_lookup(/p\.zccfo\.com/) or
		cuckoo.network.dns_lookup(/n\.52bangke\.com/) or
		cuckoo.network.dns_lookup(/m\.hothomemonkey\.com/) or
		cuckoo.network.dns_lookup(/p\.bpai360\.com/) or
		cuckoo.network.dns_lookup(/p\.sportnotlike\.com/) or
		cuckoo.network.dns_lookup(/p\.aoziclub\.com/) or
		cuckoo.network.dns_lookup(/p\.kakaoya\.com/) or
		cuckoo.network.dns_lookup(/n\.migodycb\.com/) or
		cuckoo.network.dns_lookup(/m\.justforsomefun\.com/) or
		cuckoo.network.dns_lookup(/p\.shuyuan168\.com/)
}


rule koodous_t: official
{
	meta:
		description = "This rule detects the NetWire Android RAT, used to show all Yara rules potential"
		sample = "41c4c293dd5a26dc65b2d289b64f9cb8019358d296b413c192ba8f1fae22533e "
	strings:
		$a = {41 68 4D 79 74 68}
	condition:
		androguard.package_name("ahmyth.mine.king.ahmyth") and
		not file.md5("c99ccf4d61cefa985d94009ad34f697f") and 
		$a 
}


rule leadbolt_b: advertising
{
	meta:
		description = "Leadbolt"
	condition:
		androguard.url(/http:\/\/ad.leadbolt.net/)
}


rule dowgin_c:adware android
{
    meta:
        author = "https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        sample = "4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70"
        sample2 = "cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83"
        sample3 = "d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf"
        sample4 = "cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b"
    strings:
        $a = "http://112.74.111.42:8000"
        $b = "SHA1-Digest: oIx4iYWeTtKib4fBH7hcONeHuaE="
        $c = "ONLINEGAMEPROCEDURE_WHICH_WAP_ID"
        $d = "http://da.mmarket.com/mmsdk/mmsdk?func=mmsdk:posteventlog"
    condition:
        all of them
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.
	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
rule fake_facebook_a: fake android
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Facebook")
		and not androguard.certificate.sha1("A0E980408030C669BCEB38FEFEC9527BE6C3DDD0")
}
rule fake_facebook_2_a: fake android
{
	meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		description = "Detects fake facebook applications"
		hash_0 = "7be33c2d27121968d2f7081ae2b04965238a3c15c7aae62d006f629d64e0b58e"
		hash_1 = "c1264c689393880361409eb02570fd49bec91c88569d39062e13c0c8ae0e1806"
		hash_2 = "70d5cc909d5718674474a54b44f83bd194cbdd2d99354d52cd868b334fb5f3de"
		hash_3 = "38e757abd5e015e3c3690ea0fdc2ff1e04b716651645a8c4ca6a63185856fe29"
		hash_4 = "ba0b8fe37b4874656ad129dd4d96fdec181e2c3488985309241b0449bb4ab84f"
		hash_5 = "7be33c2d27121968d2f7081ae2b04965238a3c15c7aae62d006f629d64e0b58e"
		hash_6 = "c1264c689393880361409eb02570fd49bec91c88569d39062e13c0c8ae0e1806"
		hash_7 = "7345c3124891b34607a07e93c8ab6dcbbf513e24e936c3710434b085981b815a"
	condition:
		androguard.app_name("Facebook") and
		not androguard.package_name(/com.facebook.katana/) and 
		not androguard.certificate.issuer(/O=Facebook Mobile/)	
}
rule fake_instagram_a: fake android
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Instagram")
		and not androguard.certificate.sha1("76D72C35164513A4A7EBA098ACCB2B22D2229CBE")
}
rule fake_king_games_a: fake android
{
	condition:
		(androguard.app_name("AlphaBetty Saga")
		or androguard.app_name("Candy Crush Soda Saga")
		or androguard.app_name("Candy Crush Saga")
		or androguard.app_name("Farm Heroes Saga")
		or androguard.app_name("Pet Rescue Saga")
		or androguard.app_name("Bubble Witch 2 Saga")
		or androguard.app_name("Scrubby Dubby Saga")
		or androguard.app_name("Diamond Digger Saga")
		or androguard.app_name("Papa Pear Saga")
		or androguard.app_name("Pyramid Solitaire Saga")
		or androguard.app_name("Bubble Witch Saga")
		or androguard.app_name("King Challenge"))
		and not androguard.certificate.sha1("9E93B3336C767C3ABA6FCC4DEADA9F179EE4A05B")
}
rule fake_market_b: fake android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		androguard.package_name("com.minitorrent.kimill") 
}
rule fake_minecraft_a: fake android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		( androguard.app_name("Minecraft: Pocket Edition") or 
			androguard.app_name("Minecraft - Pocket Edition") )
		and not androguard.package_name("com.mojang.minecraftpe")
}
rule fake_whatsapp_a: fake android
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}


rule sandrorat_a
{
	meta:
		description = "This rule detects SandroRat samples"
	strings:
		$a = "SandroRat"
	condition:
		$a
}


rule koodous_u: official
{
	condition:
		androguard.certificate.sha1("74D37EED750DBA0D962B809A7A2F682C0FB0D4A5") 
}


rule koodous_v: official
{
	meta:
		description = "This rule detects the cib bank apk application"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name(/com.cib.bankcib/)
}


rule sample_a
{
	meta:
		description = "sample"
	strings:
		$a = "185.62.188.32"
		$b = "TYPE_SMS_CONTENT"
		$c = "getRunningTasks"
	condition:
		$b and ($a or $c)
}


rule regla_practica_a
{
	meta:
		description = "PracticaC"
		sample = "7dab21d4920446027a3742b651e3ef8d"
	strings:
		$string_a = "3528-3589"
		$string_b = "/app/remote/forms/"
		$string_c = "IIII"
		$string_d = "slempo"
	condition:
		$string_a and $string_b and $string_c and $string_d
		}


rule taskhijack3_a: official
{
	meta:
		date = "2018-02-09"
		description = "Task Hijack #HST3 spoofing"
		reference = "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf"
		reference1 = "Power by dmanzanero"
	strings:
		$a = /taskAffinity\s*=/
		$b = /allowTaskReparenting\s*=/
		$file = "AndroidManifest.xml"
	condition:
		$file and ($a or $b)
}


rule BankBot_c: banker
{
	meta:
		description = "bankbot samples"
	strings:
		$strings_a = "de.dkb.portalapp"
		$strings_b = "de.adesso.mobile.android.gadfints"
		$strings_c = "de.commerzbanking.mobil"
		$strings_d = "de.ing_diba.kontostand"
		$strings_e = "de.postbank.finanzassistent"
		$strings_f = "com.isis_papyrus.raiffeisen_pay_eyewdg"
	condition:
		2 of ($strings_*)
}


rule suoji_a
{
	meta:
		description = "suoji"
	strings:
		$a = "&#x9501;&#x673A;&#x751F;&#x6210;&#x5668;"
	condition:
		$a
}


rule bzwbk_a
{
	meta:
		description = "1st test yara rule for detect all bzwbk banking app"
	condition:
		androguard.app_name(/bzwbk/) or
		androguard.app_name(/bzwbk24/)or
		androguard.app_name(/BZWBK24/) or
		androguard.app_name(/BZWBK/)or 
		androguard.app_name(/bzwbk mobile/) or
		androguard.app_name(/bzwbk24 mobile/)or
		androguard.app_name(/BZWBK24 mobile/) or
		androguard.app_name(/BZWBK mobile/)or
		androguard.app_name("bzwbk*")or
		androguard.app_name(/bzwbk*/)
}


rule SpyHuman_a {
   meta:
      description = "spyhuman - from files Secure Service 10.11.apk, Secure Service 10.6.apk, Secure Service 10.5.apk, Secure Service 10.4.apk, Secure Service 10.1.apk, Secure Service 10.8.apk, Secure Service 10.17.apk, Secure Service 10.3.apk, Secure Service 10.0.apk, Secure Service 10.2.apk, Secure Service 10.10.apk, Secure Service 10.16.apk, Secure Service 10.15.apk, Secure Service 10.14.apk, Secure Service 10.7.apk, Secure Service 10.9.apk"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2018-09-21"
      hash1 = "0602b0039b80d539d0218aa3572034cc98cf6c9eec160299d8acdb3867c66991"
      hash2 = "ab55fa9a540d6c6513fb46d410bda6d53dff9ce13ebe9d1cc9b51930c098050f"
      hash3 = "5498c8dc93293991c1799b2d7f1849a90d333a694d862a47960f2ec4c854d0d9"
      hash4 = "fc54f35982137778b414fc8bba37d35b781c57ac9a65ff8419aabc5b036495cc"
      hash5 = "81605a37523525879ce7c1dd5a90645983aaf0030c7d05192a0f6e1584d25828"
      hash6 = "df0a702836a645a14bb0ebe9a7206b0c9019282d5d08b0c7224adf6398e6feda"
      hash7 = "a636de7408823cd71856c15f41a3f72e994ffb75adb197a112f92c47996be457"
      hash8 = "5c9aef9eed594101f84e7e0117c7929f5b5c579dde52497018d61f4bb4a121c8"
      hash9 = "4702cd8466e4103d36a8583ba522d729dd657ae0e3580c43d5823b32ce8182ad"
      hash10 = "612704da90c579b69d7d8395d4d2f257922333c6a6dcbe2d1dd59a6ced5f32f6"
      hash11 = "96a07428171d06fce2e5941027dd6087bf4e6a30efbbd4be69e45d99359e64dc"
      hash12 = "23b4351b716e7dbede06c467081663a57bec5dbdbcd4a90bc7b01eeaf5f2e246"
      hash13 = "02787e2002e3721723abd42073031c884da5f76ec715c9f70c6656ccfd481bfe"
      hash14 = "825f7ba60108af936aa73b40862b33ac6d8a27ce7f1117feacf35b45b0a6e292"
      hash15 = "56c5129b7a151c86a12c8808b0dc7c41e32212362ca6c053b4fe6415a9621ed1"
      hash16 = "43d58b421de1e558e9a4b01210d9a15d9a6029762ea574d7a1236dcfe37be5fc"
   strings:
      $s1 = "HH547604601335-t88lg026s1s4ukkcvp1hijjv3jb0qulo.apps.googleusercontent.com" fullword ascii
      $s2 = "BBTarget Device is not registered. Please login or register account." fullword ascii
      $s3 = "Please click button Register to create one account of spyhuman.com. Else if you have an account then click button Login to assig" ascii
      $s4 = "Please click button Register to create one account of spyhuman.com. Else if you have an account then click button Login to assig" ascii
      $s5 = "vvYou can monitor this device from your computer or iPhone/iPad or other mobile phones by visiting website spyhuman.com." fullword ascii
      $s6 = "www.spyhuman.com" fullword ascii
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c014 79.156797, 2014/08/" ascii
      $s8 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c014 79.156797, 2014/08/" ascii
      $s9 = "DDPlease wait to retrieve information from server (site spyhuman.com)." fullword ascii
      $s10 = "<<Register your device with spyhuman.com and start monitoring." fullword ascii
      $s11 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c014 79.156797, 2014/08/" ascii
      $s12 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s13 = "##safesecureservice-702df.appspot.com" fullword ascii
      $s14 = "..https://safesecureservice-702df.firebaseio.com" fullword ascii
      $s15 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s16 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" fullword ascii
      $s17 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" fullword ascii
      $s18 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" fullword ascii
      $s19 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" fullword ascii
      $s20 = "Control Panel: www.spyhuman.com" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}


rule Android_Trojan_FakeAd_B_a
{
	meta:
		description = "Rule used to detect jio and paytm fakeapp"
		source = "Lastline"
		Author = "Anand Singh"
		Date = "24/04/2019"
	strings:
		$a1 = "JIO NUMBER[local]"
		$a2 = "JioWebService/rest"
		$a3 = "WhatsApp not Installed"
		$a4 = "Congratulations!!"
		$b = "Lme/zhanghai/android/materialprogressbar/"
	condition:
		2 of ($a*) and $b
}


rule WhatsApp_a: Virus
{
	condition:
	   androguard.url("google.com/iidKZ.KxZ/=-Z[")
}


rule Trojan_b: apt36
{
	meta:
        description = "Trojan targeting Banks with Overlays"
		source = ""
	strings:
		$c2_1 = "ColoRich" nocase
		$c2_2 = "taothao" nocase
		$c2_3 = "tran hien" nocase
		$c2_4 = "taothao2012@gmail.com" nocase
		$c2_5 = "alexhien.com@gmail.com" nocase
	condition:
		1 of ($c2_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
		)
}


rule ransomware_c: svpeng
{
	meta:
		description = "Ransomware"
		in_the_wild = true
	strings:
		$a =  {6e 64 20 79 6f 75 72 27 73 20 64 65 76 69 63 65 20 77 69 6c 6c 20 72 65 62 6f 6f 74 20 61 6e 64}
		$b = "ADD_DEVICE_ADMI"
	condition:
		$a and $b
}


rule rusSMS_a
{
	meta:
		description = "Russian app, connects to remote server (http://googlesyst.com/) and gets the user to answer SMS (and a fake funds balance). Apparently, to unlock the app you have to send reiterate SMS."
	strings:
		$a = "http://googlesyst.com/"
		$b = "mxclick.com"
	condition:
		$a and $b
}


rule New_Marcher_May_17_a
{
	meta:
		description = "This rule detects new Marcher samples with jumbled Receiver and Service names"
		sample = "68ce40e9bdb43b900bf3cb1697b37e29"
	condition:
		androguard.service(/\.[a-z]{1}[0-9]{3}[a-z]{1}\b/) and
		androguard.receiver(/\.[a-z]{1}[0-9]{3}[a-z]{1}\b/)
}


rule non_named_a
{
	meta:
	description = "This rule detects something"
	strings:
		$a = "SHA1-Digest: D1KOexBGmlpJS53iK7KjJcyzt7o="
	condition:
		all of them
}


rule OmniRat_a: Certs
{
    condition:
        androguard.certificate.sha1("B17BACFB294A2ADDC976FE5B8290AC27F31EB540")
}


rule koodous_w: official
{
	meta:
		description = "This rule detects omnirat trojan"
		sample = "43e9ffbb92929e3abd652fdd03091cc4f63b33976c7ddbba482d20468fee737a"
	strings:
		$a = "com.android.engine"
		$b = "divideMessage"
	condition:
		$a and $b and 
		androguard.permission(/com\.android\.launcher\.permission\.UNINSTALL_SHORTCUT/) and
		androguard.permission(/com\.android\.browser\.permission\.READ_HISTORY_BOOKMARKS/) and
		androguard.permission(/com\.android\.browser\.permission\.WRITE_HISTORY_BOOKMARKS/) and
		androguard.permission(/com\.android\.launcher\.permission\.INSTALL_SHORTCUT/) and
		androguard.permission(/android\.permission\.TRANSMIT_IR/) and
		androguard.permission(/android\.permission\.PROCESS_OUTGOING_CALLS/) and
		androguard.permission(/android\.permission\.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android\.permission\.BLUETOOTH/) and
		androguard.permission(/android\.permission\.CAMERA/) and
		androguard.permission(/android\.permission\.INTERNET/) and
		androguard.permission(/android\.permission\.BLUETOOTH_ADMIN/) and
		androguard.permission(/android\.permission\.MANAGE_ACCOUNTS/) and
		androguard.permission(/android\.permission\.SEND_SMS/) and
		androguard.permission(/android\.permission\.WRITE_SMS/) and
		androguard.permission(/android\.permission\.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android\.permission\.SET_WALLPAPER/) and
		androguard.permission(/android\.permission\.READ_CALL_LOG/) and
		androguard.permission(/android\.permission\.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android\.permission\.RECORD_AUDIO/) and
		androguard.permission(/android\.permission\.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android\.permission\.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android\.permission\.AUTHENTICATE_ACCOUNTS/) and
		androguard.permission(/android\.permission\.CALL_PHONE/) and
		androguard.permission(/android\.permission\.READ_PHONE_STATE/) and
		androguard.permission(/android\.permission\.READ_SMS/) and
		androguard.permission(/android\.permission\.VIBRATE/) and
		androguard.permission(/android\.permission\.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android\.permission\.ACCESS_WIFI_STATE/) and
		androguard.permission(/android\.permission\.WAKE_LOCK/) and
		androguard.permission(/android\.permission\.CHANGE_WIFI_STATE/) and
		androguard.permission(/android\.permission\.RECEIVE_SMS/) and
		androguard.permission(/android\.permission\.READ_CONTACTS/) and
		androguard.permission(/android\.permission\.DOWNLOAD_WITHOUT_NOTIFICATION/) and
		androguard.permission(/android\.permission\.GET_ACCOUNTS/)
}


rule omnirat_dropper_a
{
	meta:
		description = "This rule detects omnirat dropper"
		sample = "0b7e5cca82d33429aa1b81f7ae0a707d30b984c083c4ba033a00d2ca637fa8b1"
		sample2 = "244bcc4d39eed69ae215b5ad977209d87f3b7b81a2fd04b961715170d805b38b"
		reference = "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-control-of-devices/"
	strings:
		$a = "/android.engine.apk"
		$b = "21150715091744Z0"
	condition:
		all of them
}


rule OmniRAT_a: RAT
{
	meta:
		description = "OmniRAT"
	strings:
		$name = "com.android.engine"
		$s_1 = "DeviceAdmin"
		$s_2 = "SMSReceiver"
	condition:
		2 of ($s_*)
		and $name
		and androguard.permission(/android.permission.RECEIVE_SMS/)
		and androguard.permission(/android.permission.READ_CONTACTS/)
		and androguard.permission(/android.permission.SEND_SMS/)
		and androguard.permission(/android.permission.WRITE_SMS/)
		and androguard.permission(/android.permission.BLUETOOTH_ADMIN/)
		and androguard.permission(/android.permission.MANAGE_ACCOUNTS/)
		and androguard.filter(/android.app.action.DEVICE_ADMIN_ENABLED/)
		and androguard.filter(/android.provider.Telephony.SMS_RECEIVED/)
		and androguard.filter(/android.intent.action.BOOT_COMPLETED/)
}


rule test_a: adware
{
    condition:
		androguard.app_name(/{d0 a3 d1 81 d1 82 d0 b0 d0 bd d0 be d0 b2 d0 ba d0 b0}/) or androguard.package_name(/com\.tujtr\.rtbrr/)
}


rule packers_f: i360
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$i360_1 = "libjiagu.so"
		$i360_2 = "libjiagu_art.so"
	condition:
		2 of them
}


rule paymentsSMS_a
{
	meta:
		description = "Connects to remote server and tries to charge the user using his data and sends SMS"
	strings:
		$a = "http://112.126.69.51/imei_mobile.php?imei="
		$b = "http://api.taomike.com/install_zhubao.php"
		$c = "http://112.126.69.51/order_lost.php"
		$d = "http://112.126.69.51/install_report.php"
		$e = "http://112.74.111.56:9039/gamesit/puburl"
		$f = "http://194.87.232.236/mos_metro/?deviceID="
	condition:
		 androguard.url(/112\.126\.69\.51/) or $a or $b or $c or $d or $e or $f
}


rule ruleNumber1_a{
    meta:
        author = "Captain Picard"
        date = "12 Dec 2517"
        original = "NGS-784"
    condition:
        androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
        androguard.activity("com.software.application.ShowLink") and 
        androguard.displayed_version("1.0") and 
        androguard.filter("android.intent.action.DATA_SMS_RECEIVED") and 
        androguard.filter("android.intent.action.BOOT_COMPLETED") and 
        androguard.functionality.mcc.method(/onCreate/) and 
        androguard.filter("com.software.CHECKER") and androguard.functionality.dynamic_broadcast.class(/Lcom\/software\/application\/Actor\;/) and 
        androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ v2\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 
        androguard.functionality.dynamic_broadcast.method(/acquire/) and 
        androguard.functionality.mcc.class(/Lcom\/software\/application\/Main\;/) and 
        androguard.filter("android.intent.action.MAIN") and 
        androguard.functionality.dynamic_broadcast.method(/onReceive/) and 
        androguard.permission("android.permission.READ_SMS") and 
        androguard.activity("com.software.application.Main") and 
        androguard.permission("android.permission.INTERNET") and 
        androguard.functionality.socket.class(/Lcom\/software\/application\/Actor\;/) and 
        androguard.functionality.mcc.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getNetworkOperator\(\)Ljava\/lang\/String\;/) and 
        androguard.functionality.socket.method(/report/) and 
        androguard.main_activity("com.software.application.Main") and 
        androguard.number_of_activities == 3 and 
        androguard.package_name("com.software.application") and 
        androguard.permission("android.permission.RECEIVE_SMS") and 
        androguard.permission("android.permission.SEND_SMS") and 
        androguard.receiver("com.software.application.Checker") and 
        androguard.receiver("com.software.application.Notificator") and 
        androguard.permission("android.permission.READ_PHONE_STATE") and 
        androguard.receiver("com.software.application.SmsReceiver")
}


rule PimentoRoot_a: rootkit
{
	condition:
		androguard.url(/http:\/\/webserver\.onekeyrom\.com\/GetJson\.aspx/)
}


rule PinguLocker_a
{
	meta:
		description = "This rule detects a locker for Android"
		sample = "aa0b52f66982a0d22d724ee034d0a36296f1efb452e9a430bd23edbc9741b634"
	strings:
		$a = "res/anim/tvanim.xmlPK"
		$b = "access$L1000001"
		$c = "access$L1000002"
		$d = "res/layout/newone.xmlPK"
		$e = "Created-By: 1.0 (Android SignApk)"
	condition:
		all of them
}


rule plantsvszombies_a:SMSFraud
{
	meta:
		sample = "ebc32e29ceb1aba957e2ad09a190de152b8b6e0f9a3ecb7394b3119c81deb4f3"
	condition:
		androguard.certificate.sha1("2846AFB58C14754206E357994801C41A19B27759")
}


rule Porn_a: official
{
	meta:
		description = "Experimental rule about Porn samples"
		sample = "-"
	strings:
		$a = "porn" nocase
	condition:
		androguard.package_name(/porn/) and $a 
		or (androguard.package_name(/porn/) and $a and androguard.permission(/android.permission.SEND_SMS/))
}


rule PornApps_a
{
	meta:
		description = "Rule to detect certain Porn related apps"
		sample = "baea1377a3d6ea1800a0482c4c0c4d8cf50d22408dcf4694796ddab9b011ea14"
	strings:
		$a = "/system/bin/vold"
	condition:
		(androguard.activity(/.HejuActivity/) and $a)or
		androguard.service(/\.cn\.soor\.qlqz\.bfmxaw\.a\.a\.c\.d/)
}


rule PornDroid_a
{
	meta:
		description = "This rule detects PornDroid by Childporn Picture"
		sample = "9A51993C3AE511FCE77CF2373DA4056512FC36ED05E5374DCA57256BEDC17609"
	strings:
		$a = "SHA1-Digest: vvk8TC2RhKdWraPlu6Egxbqc4hI=" nocase
		$b = "SHA1-Digest: kEhfn3oMaOvZTWYpjZmf1aOjhkQ=" nocase
		$c = "SHA1-Digest: bCjLPQvLogt1yegnGOe70nFwVz0=" nocase
		$d = "SHA1-Digest: /llINcHHI5e4YRLrLjH+xSllEtg=" nocase
	condition:
		1 of them
}


rule PornLock_a
{
	meta:
		description = "Rule to detect specific Porn related Lockscreen"
		sample = "f7c9a55d07069af95c18c8dd62b1c66568e3b79af551d95c7bf037a107e6526e"
	strings:
		$r = "res/xml/device_admin_data.xml"
		$b = "Update"
		$c = "XXX"
		$d = "Porn"
		$e = "Adult"
	condition:
	($r and androguard.service(/.Service\d{2}/) and $b and $c) or ($r and androguard.service(/.Service\d{2}/) and $b and $d) or ($r and androguard.service(/.Service\d{2}/) and $b and $e)
}


rule PornSlocker_b
{
	meta:
		description = "This rule detects some common used pictures or other files in SLocker / PornLocker variants"
strings:
	  $ = "SHA1-Digest: 7IsBe9rxRK/MPmdDkVLoGDUgc9U="
	  $ = "SHA1-Digest: MVIz+0h8/7uJg6FzxezlLYeQ8DI="
	  $ = "SHA1-Digest: QmH6OE16ItwdO6nLHXdCYYsWZlw="
	  $ = "SHA1-Digest: krfyZeqOcVdXKp14LSPboF/qBAM="
	  $ = "SHA1-Digest: oKndfTj8AicZPlKCRIHBVbAAz2Y="
	  $ = "SHA1-Digest: LbMVl56xHfaJYHRPTu4qeKfQJQQ="
	  $ = "SHA1-Digest: VmDAQ7bv9tQkB5FHW886FsgadFQ="
      $ = "SHA1-Digest: kQM7/tmBPdTILxiwYuvQvwwPAfo="
	  $ = "SHA1-Digest: lOoGSYGEUN3eTMcSPE3iNX7lw4Q="
	  $ = "SHA1-Digest: cPVeLhm/BlUOhKZRfUx8WGvyT90="
      $ = "SHA1-Digest: v4/pYdRCXHZraLWFGWENv0ie1vk="
      $ = "SHA1-Digest: zoYgXzxdaIJIyoslwVSC/IlxAtw="
	  $ = "SHA1-Digest: xA5tmmIrL9ex9WSLmPHtmDXiamc="
	  $ = "SHA1-Digest: sOkywP18/kCq9tn0nZ4JywzaWno="
	  $ = "SHA1-Digest: PXi8kScvGYUTpnMFZDl5S62ZM8k="
	  $ = "SHA1-Digest: PcP6KWHRgXLam8J5uO6lRxuBvPc="
	  $ = "SHA1-Digest: J0lAOGynBbj50bZ/VRkk2vx9Ysc="
	  $ = "SHA1-Digest: Kb+VcnqOoUdfJkW7ZMhXoJADQQ0="
      $ = "SHA1-Digest: sBLBhcd7IpCFfuuLRAuBOzOQ4J4="
	condition:
		2 of them
}


rule PornoLocker_a
{
	condition:
		cuckoo.network.dns_lookup(/soso4ki.ru/) or
		cuckoo.network.dns_lookup(/zapisulka.ru/)
}


rule Porn_receiver1_a
{
	meta:
		description = "Catches Porn apps - 0679099c90621db26d92bbb2467542a1"
	condition:
		(
		 androguard.receiver(/ts\.xd\.com\.Dw/) and
		 androguard.receiver(/com\.zxhy\.zf\.r\.D/) and
		 androguard.activity(/com\.test\.zepasub\.JActivity/) and
		 androguard.activity(/com\.test\.hown\.NActivity/) and
		 androguard.activity(/ys\.cs\.com\.Xs/)
		 )
}


rule postepay_smsFraud_a
{
	meta:
		description = "Yara detection for PostePay SMS-fraud"
	condition:		
		androguard.package_name("me.help.botfix") and
		androguard.certificate.sha1("F3B7734A4BADE62AD30FF4FA403675061B8553FF") and
		androguard.receiver(/\.SmsListener/) and 
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) 
}


rule packers_g: tencent
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$tencent_1 = "libmain.so"
		$tencent_2 = "libshell.so"
	condition:
		2 of them
}


rule podec_fobus_a: smstrojan
{
	meta:
		description = "Android.Podec SMS Trojan bypasses CAPTCHA sample"
		url = "http://contagiominidump.blogspot.com.es/2015/03/androidpodec-sms-trojan-bypasses.html"
		sample = "5616840a66ce35ac1f94b5c1737935931dad8a49fc7d35d21128b9a52f65e777"
	condition:
		androguard.permission(/android.permission.SEND_SMS/)
		and androguard.certificate.sha1("671FEA3319B82E5325AB19218188EC35CC2619E5")
		and androguard.url("https://api.rollbar.com/api/1/items/")
}


rule proxy_spy_a: trojan
{
	meta:
		description = "This rule detects http://b0n1.blogspot.com.es/2015/04/android-trojan-spy-goes-2-years.html"
		sample = "00341bf1c048956223db2bc080bcf0e9fdf2b764780f85bca77d852010d0ec04"
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.activity(/\.*proxy\.MainActivity/i) and
		androguard.url(/proxylog\.dyndns\.org/)	
}


rule khashayar_talebi_a
{
	meta:
		description = "Possible Threats, Domains registered for khashayar.talebi@yahoo.com"
	strings:
		$ = "tmbi.ir"
		$ = "masirejavan.ir"
		$ = "clipmobile.ir"
		$ = "razmsport.ir"
		$ = "norehedayat.ir"
		$ = "dlappdev.ir"
		$ = "telememberapp.ir"
		$ = "btl.ir"
		$ = "niazeparsi.ir"
		$ = "imdbfa.ir"
		$ = "thecars.ir"
		$ = "rahaserver.ir"
		$ = "mehrayen.ir"
	condition:
		1 of them
}


rule xolosale_a
{
	strings:
		$ = "919211722715"
		$ = "servernumber"
		$ = "xolo"
	condition:
		( androguard.url(/pu6b.vrewap.com:1337/i) or
		androguard.url(/pu6a.vrewap.com:1337/i) ) 
		or 
		all of them
}


rule clicksummer_b
{
	meta:
		description = "test clicksummer"
	strings:
		$a = "statsevent.clickmsummer.com:80/log"
		$b = "54.149.205.221:8080/MobiLog/log"
	condition:
 		1 of them
}
rule SMS1_a
{
	meta:
		description = "test com.pigeon.pimento.pimple"
	strings:
		$a = "SHA1-Digest: Itv2yusaL6KWWE/TLZFej7FVCO0="
	condition:
 		1 of them
}


rule QuadRooter_a
{
	meta:
		description = "QuadRooter"
		sample = ""
	strings:
		$a = "/dev/kgsl-3d0"
	condition:
		$a
}


$a = "/cellphone-tips\.com/"
rule random_a: adware
{
    condition:
        androguard.url(/cellphone-tips\.com/) or 
		$a
}


rule FBI_a: ransomware
{
	meta:
		sample = "d7c5cb817adfa86dbc9d9c0d401cabe98a3afe85dad02dee30b40095739c540d"
	strings:
		$a = "close associates will be informed by the authorized FBI agents" wide ascii
		$b = "ed on the FBI Cyber Crime Department's Datacenter" wide ascii
		$c = "All information listed below successfully uploaded on the FBI Cyber Crime Depar" wide ascii
	condition:
		all of them
}


rule leakerlocker_a
{
	meta:
		description = "https://securingtomorrow.mcafee.com/mcafee-labs/leakerlocker-mobile-ransomware-acts-without-encryption/"
		sample = "486f80edfb1dea13cde87827b14491e93c189c26830b5350e31b07c787b29387"
	strings:
		$ = "updatmaster.top/click.php?cnv_id" nocase
		$ = "goupdate.bid/click.php?cnv_id" nocase
		$ = "personal data has been deleted from our servers and your privacy is secured" nocase
	condition:
		2 of them
}


rule fbilocker_a {
	strings:	
		$a1 = "comdcompdebug.500mb.net/api33"
		$a2 = "itsecurityteamsinc.su"
		$a3 = "api.php"
    condition:
        androguard.certificate.sha1("A4DF11815AF385578CEC757700A3D1A0AF2136A8") or
		2 of ($a*)
}


rule ransomware_d
{
	meta:
		description = "This rule detects ransomware android app"
		sample = "b3a9f2023e205fc8e9ff07a7e1ca746b89a7db94a0782ffd18db4f50558a0dd8"
	strings:
		$a = "You are accused of commiting the crime envisaged"
	condition:
		androguard.package_name("com.android.locker") or
		androguard.package_name("com.example.testlock") or
		androguard.url(/api33\/api\.php/) or 
		$a
}


rule ransomware_e
{
	meta:
		description = "This rule detects Russian ransomware (also in AndroidTV)"
		sample = "7fcf3fb097fe347b30bb7011ebb415bb43711a2a8ffde97824528b62a6fdcebd "
		source = "https://www.zscaler.com/blogs/research/new-android-ransomware-bypasses-all-antivirus-programs?utm_source=Social-media&utm_medium=twitter&utm_content=007v94o87z0zb90&utm_campaign=Q3Y17+Blog&utm_ID=UI"
	strings:
		$a = "VISA QIWI WALLET" wide ascii
	condition:
		(androguard.package_name("ru.ok.android") or
		androguard.package_name("com.nitroxenon.terrarium") or
		androguard.package_name("com.cyanogenmod.eleven"))
		and $a
}


rule ransomware_f
{
  meta:
      author = "https://www.twitter.com/SadFud75"
  strings:
      $s1 = "The penalty set must be paid in course of 48 hours as of the breach" nocase
      $s2 = "following violations were detected" nocase
      $s4 = "all your files are encrypted" nocase
      $s5 = "your device has been blocked" nocase
      $s6 = "department of justice" nocase
      $s7 = "remaining time to pay" nocase
      $s8 = "your phone has been blocked" nocase
  condition:
      any of them or androguard.service("com.h.s")
}


rule ransomware_g
{
	meta:
		description = "This rule detects ijimu.com and bluerobo.com see source"
		sample = "c2f5175eb7a9833bbba8ee6652e9fa69a0026fb18a614f96a4910380a5960d3f"
		source = "http://www.hotforsecurity.com/blog/android-malware-promises-porn-but-roots-device-and-installs-other-malware-13900.html"
	strings:
		$a = "http://root.ijimu.com:7354/"
		$b = "http://p.bluerobo.com:7354/"
		$c = "http://p2.bluerobo.com:7354/"
	condition:
		1 of them
}


rule ransomware_h: svpeng
{
	meta:
		description = "Ransomware"
		in_the_wild = true
	strings:
		$a =  {6e 64 20 79 6f 75 72 27 73 20 64 65 76 69 63 65 20 77 69 6c 6c 20 72 65 62 6f 6f 74 20 61 6e 64}
		$b = "ADD_DEVICE_ADMI"
	condition:
		$a and $b
}


rule Ransomware_a: banker
{
	meta:
		description = "Ransomware Test 2"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_a = "!2,.B99^GGD&R-"
		$strings_b = "22922222222222222222Q^SAAWA"
		$strings_c = "t2222222222229222Q^SAAWA"
	condition:
		any of ($strings_*)
}


rule Ransomware_b
{
	meta:
		description = "https://www.zscaler.de/blogs/research/new-android-ransomware-bypasses-all-antivirus-programs"
	strings:
		$a = "SHA1-Digest: xIzMBOypVosF45yRiV/9XQtugE0=" nocase
	condition:
		1 of them
}
rule Locker_b
{
	strings:
		$a = "SHA1-Digest: CbQPkm4OYwAEh3NogHhWeN7dA/o=" nocase
	condition:
		1 of them
}


rule ransomware_i: from_cromosome
{
	meta:
		description = "This rule detects ransomware"
		sample = "created with the help of cromosome.py and a ransomware dataset with the families fakedefender, kiler, pletor, ransombo, scarepackage, slocker and svpeng "
	strings:
	$cromo_0 ="android.app.device_admin"
	$cromo_1 ="AndroidManifest.xmlPK"
	$cromo_2 ="$Landroid/telephony/TelephonyManager;"
	$cromo_3 ="$android.permission.BIND_DEVICE_ADMIN"
	$cromo_4 ="*Landroid/content/SharedPreferences$Editor;"
	$cromo_5 ="getSharedPreferences"
	$cromo_6 ="'android.app.action.DEVICE_ADMIN_ENABLED"
	$cromo_7 ="&android.permission.SYSTEM_ALERT_WINDOW"
	$cromo_8 =")android.permission.RECEIVE_BOOT_COMPLETED"
	$cromo_9 =")android.permission.WRITE_EXTERNAL_STORAGE"
	$cromo_10 ="$android.intent.action.BOOT_COMPLETED"
	$cromo_11 ="android.intent.category.HOME"
	$cromo_12 ="android.permission.GET_TASKS"
	$cromo_13 ="#Landroid/content/SharedPreferences;"
	$cromo_14 ="android.permission.READ_CONTACTS"
	$cromo_15 ="Landroid/os/Build;"
	$cromo_16 ="#android.permission.READ_PHONE_STATE"
	$cromo_17 ="'Landroid/app/admin/DevicePolicyManager;"
	$cromo_18 ="'Landroid/app/admin/DeviceAdminReceiver;"
	condition:
		16 of them
}


rule Raxir_a: ccm
{
        meta:
        description = "This rule was produced by CreateYaraRule and CommonCode, it detects RAXIR string decription routine"
        author = "_hugo_gonzalez_ "
		sample = "07278c56973d609caa5f9eb2393d9b1eb41964d24e7e9e7a7e7f9fdfb2bb4c31"
/*		source_ code = 
Lcom/google/gson/JsonNull; 
================================================== 
('concat', '36') 									
----------------------------------------			
public static String concat(int p7, String p8)		
    {												
        v0 = (p7 - 7);								
        v4 = p8.toCharArray();						
        v5 = v4.length;								
        v2 = v0;									
        v0 = 0;										
        while (v0 != v5) {							
            v6 = ((v2 & 95) ^ v4[v0]);				
            v3 = (v2 + 9);							
            v2 = (v0 + 1);							
            v4[v0] = ((char) v6);					
            v0 = v2;								
            v2 = v3;								
        }											
        return String.valueOf(v4, 0, v5).intern();
    }												
        strings :
		$S_8_12_72 = { 12 01 d8 00 ?? ?? 6e 10 ?? ?? ?? 00 0c 04 21 45 01 02 01 10 32 50 11 00 49 03 04 00 dd 06 02 5f b7 36 d8 03 02 ?? d8 02 00 01 8e 66 50 06 04 00 01 20 01 32 28 f0 71 30 ?? ?? 14 05 0c 00 6e 10 ?? ?? 00 00 0c 00 11 00 }
    condition:
        all of them
}


rule detection_c
{
    strings:
		$d = "twitter.com"
		$ = /103.239.30.[0-9]{1,3}:7878/
		$ = /119.28.128.[0-9]{1,3}:7878/
		$ = /119.28.179.[0-9]{1,3}:7878/
		$ = /119.28.25.[0-9]{1,3}:7878/
		$ = /119.28.54.[0-9]{1,3}:7878/
		$ = /146.185.241.[0-9]{1,3}:7878/
		$ = /185.165.29.[0-9]{1,3}:7878/
		$ = /185.165.30.[0-9]{1,3}:7878/
		$ = /185.4.29.[0-9]{1,3}:7878/
		$ = /185.189.58.[0-9]{1,3}:7878/
		$ = /185.35.137.[0-9]{1,3}:7878/
		$ = /185.126.200.[0-9]{1,3}:7878/
		$ = /185.100.222.[0-9]{1,3}:7878/
		$ = /185.243.243.[0-9]{1,3}:7878/
		$ = /188.0.236.[0-9]{1,3}:7878/
		$ = /109.236.82.[0-9]{1,3}:7878/
		$ = /146.0.72.[0-9]{1,3}:7878/
		$ = /37.1.201.[0-9]{1,3}:7878/
		$ = /49.51.133.[0-9]{1,3}:7878/
		$ = /49.51.137.[0-9]{1,3}:7878/
		$ = /5.101.1.[0-9]{1,3}:7878/
		$ = /5.188.211.[0-9]{1,3}:7878/
		$ = /5.188.62.[0-9]{1,3}:7878/
		$ = /91.218.114.[0-9]{1,3}:7878/
		$ = /46.161.42.[0-9]{1,3}:7878/
		$ = /85.119.150.[0-9]{1,3}:7878/
		$ = /95.213.251.[0-9]{1,3}:7878/
		$x = "ffpanel.ru/client_ip.php?key"
    condition:
		$x or ($d and 1 of ($))
}


rule reddit_adware_a
{
	meta:
		description = "Reddit adware"
		sha = "1dfa6b8267733667d1a6b838c235e10146ae33e708a2755240947b8047bcc39f"
	strings:
        $a_1 = "Telephony SECRET_CODE" fullword
        $a_2 = "Ti92T_77Zij_MiTik" fullword
        $a_3 = "SendTaskInfo1 content" fullword
	condition:
		all of ($a_*)
}


rule risky_android_certificates_a {
	meta:
		description="An ongoing list of certificates that are used to create adware/malware"
	condition:							androguard.certificate.sha1("81:3A:3A:D3:7D:87:AA:36:12:0D:FE:C6:41:46:C3:11:DB:5F:4C:A9") or
		androguard.certificate.issuer(/BestToolbars/) or
		androguard.certificate.sha1("8C:BD:58:1C:77:76:7B:CA:B8:0C:D4:BE:DE:DD:5F:A2:A2:28:69:E8") or 
		androguard.certificate.issuer(/android-debug/) or
		androguard.certificate.sha1("62:71:54:7B:66:8C:E8:81:20:82:49:F8:59:5F:53:15:E3:90:EB:2E") or 
		androguard.certificate.issuer(/Chineseall/) or
		androguard.certificate.sha1("94:3B:C6:E0:82:7F:09:B0:50:B0:28:30:68:5A:76:73:4E:56:61:68") or 
		androguard.certificate.sha1("AC:9B:0D:8F:AE:26:2C:90:3A:E3:37:49:C0:C1:4B:D0:9F:64:B8:22") or 
		androguard.certificate.issuer(/Internet Widgits/) or
		androguard.certificate.sha1("BF:C7:3C:8C:C6:F0:DF:CC:90:EF:8B:E4:9B:2E:17:CB:B7:85:6F:EE") or 
		androguard.certificate.issuer(/Gall me/) or
		androguard.certificate.sha1("C6:7F:8F:C6:3E:25:C1:F2:D3:D3:62:32:10:D1:26:BC:96:AF:EE:69") or 
		androguard.certificate.issuer(/Alex Popov/) or
		androguard.certificate.sha1("E0:30:A3:1B:E3:12:FF:93:8A:AF:3F:31:49:34:B1:E9:2A:F2:5D:60") or 
		androguard.certificate.issuer(/hjgjhg/) or
androguard.certificate.sha1("DB:87:39:0F:55:B3:FE:B6:D7:A0:5C:64:6B:F0:97:91:67:13:73:CC") or
androguard.certificate.sha1("06:14:68:81:20:29:0A:8F:6F:88:8A:A6:EC:24:72:AF:A6:3E:8B:66")
}


rule koodous_x: official
{
	meta:
		description = "ronash - pushe"
	condition:
		androguard.activity(/ronash/i) or
		androguard.url(/ronash\.co/)
}


rule RuClicker_a
{
	strings:
		$ = "CiLscoffBa"
		$ = "FhLpinkJs"
		$ = "ZhGsharecropperFx"
	condition:
 		all of them
}


rule russian_domain_a: adware
{
	strings:
		$a = "zzwx.ru"
	condition:
		$a
}


rule fakeInstaller_c
{
	meta:
		description = "The apps developed by this guy are fakeinstallers"
		one_sample = "fb20c78f51eb781d7cce77f501ee406a37327145cf43667f8dc4a9d77599a74d"
	condition:
		androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")
}


rule russian_a: fakeInst
{
	condition:
		androguard.certificate.sha1("D7FE504792CD5F67A7AF9F26C771F990CA0CB036")
}


rule sandrorat_b
{
	meta:
		description = "This rule detects SandroRat samples"
	strings:
		$a = "SandroRat_Configuration_Database"
		$b = "SandroRat_BrowserHistory_Database"
		$c = "SandroRat_Configuration_Database"
		$d = "SandroRat_CallRecords_Database"
		$e = "SandroRat_RecordedSMS_Database"
		$f = "SandroRat_CurrentSMS_Database"
		$g = "SandroRat_Contacts_Database"
	condition:
		any of them
}


rule SandroRat_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "21-May-2016"
		description = "This rule detects SandroRat"
		source = "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/"
	condition:
		androguard.activity(/net.droidjack.server/i) 
}


rule SandroRAT_a{
	meta :
		description = "rule for detected SandroRAT Samples"
	strings:
		$a = "SandroRat_Configuration_Database"
		$b = "SandroRat_BrowserHistory_Database"
		$c = "SandroRat_Configuration_Database"
		$d = "SandroRat_CallRecords_Database"
		$e = "SandroRat_RecordedSMS_Database"
		$f = "SandroRat_CurrentSMS_Database"
		$g = "SandroRat_Contacts_Database"
	condition:
		any of them or 
		androguard.receiver(/net.droidjack.server/i) or
		androguard.package_name("net.droidjack.server")
}


rule sandrorat_c
{
	meta:
		description = "This rule detects Sandrorat samples"
	strings:
		$a = "SandroRat"
	condition:
		$a		
}


rule ScamCampaign_ModifiedPaymentGateway_a
{
	meta:
		description = "This campaign spreads fake applications like undresser camera, modifies the payment gateway using javascript in webview to change the payment amount"
		sample = "190c8484286857f68adf6db31b7927548bef613a65376d86894f503f1d104066"
	strings:
		$SuperCamera_1 = "SuperCamera.Cameraaa, SuperCamera"
		$SuperCamera_2 = "SuperCamera.About, SuperCamera"
		$PocketTV_1 = "CustomRowView.listchanels, CustomRowView"
		$PocketTV_2 = "CustomRowView.pay, CustomRowView"
	condition:
		($SuperCamera_1 and $SuperCamera_2) or
		($PocketTV_1 and $PocketTV_2) or
		androguard.activity("md552a6ea15d8d57b628a7925702f10e901.Cameraaa") or
		androguard.activity("md5d8359e76a35968359354b626b6df299b.listchanels")		
}


rule Size_and_Permissions_a: smsfraud
{
	meta:
		description = "This rule should match applications that send SMS"
		cluster = "Type 2"
		sample1 = "d1860ea0d9c4cb70b1a73789939a3f310eb48741111132d44283ab71a424b773"
		sample2 = "c9026fee9f82e43e53c1f385ac99b427a3f4e41a5fe874275a8c80a41762aad8"
		sample3 = "136b92e2eb57a02692c06a22e1596f6fbedb6a78b14475a1ebac929b1bb57013"
	condition:
		file.size <= 5MB //and file.size >= 1MB (?)
		and androguard.number_of_permissions >= 90
		and androguard.permission(/(SEND|WRITE)_SMS/)
		and androguard.functionality.run_binary.code(/invoke-static v0, Ljava\/lang\/System;->loadLibrary(Ljava\/lang\/String;)V/)
}


rule Service_a:Gogle
{
	condition:
		androguard.service("com.module.yqural.gogle")
}


rule shedun_a
{
	meta:
		description = "Detects libcrypt_sign used by shedun"
		sample = "919f1096bb591c84b4aaf964f0374765c3fccda355c2686751219926f2d50fab"
	strings:
		$a = "madana!!!!!!!!!"
		$b = "ooooop!!!!!!!!!!!"
		$c = "hehe you never know what happened!!!!"
	condition:
		all of them
}


rule shedum_a: signature
{
	meta:
		description = "This rule detects shedun adware by common code signature method"
	strings:
	$S_7138 = { 71 10 ?? 00 ?? 00 0c ?? 6e 30 ?? 00 ?? ?? 0c ?? 6e 30 ?? 00 ?? ?? 0c ?? 11 ?? 0d 00 6e 10 ?? 00 00 00 12 ?? 28 fa }
	$S_7146 = { 71 10 ?? 00 ?? 00 0c ?? 6e ?? ?? 00 ?? ?? 0c ?? 12 ?? 6e 20 ?? 00 ?? 00 6e ?? ?? 00 ?? ?? 0c ?? 11 ?? 0d 00 6e 10 ?? 00 00 00 12 ?? 28 fa }
	$S_7142 = { 71 10 ?? 00 ?? 00 0c ?? 6e 20 ?? 00 ?? 00 0c ?? 12 ?? 6e 20 ?? 00 ?? 00 6e 30 ?? 00 ?? ?? 0e 00 0d 00 6e 10 ?? 00 00 00 28 fb }
	$S_1240 = { 12 ?? 71 10 ?? 00 ?? 00 0c ?? 6e 30 ?? 00 ?? ?? 0c 01 12 ?? 6e 30 ?? 00 ?? ?? 0c ?? 11 ?? 0d ?? 6e 10 ?? 00 ?? 00 28 fb }
	condition:
		2 of them
}


rule shiny_adware_a
{
	condition:
		androguard.package_name(/com.shiny*/) and cuckoo.network.http_request(/http:\/\/fingertise\.com/)
}


rule Shuanet_a: official
{
	meta:
		description = "This rule detects Shuanet aggresive Adware (https://blog.lookout.com/blog/2015/11/04/trojanized-adware/)"
		sample = "-"
	strings:
		$a = {4C 4F 43 41 4C 5F 44 4F 57 4E 5F 43 4F 4E 46 49 47}
		$b = {4E 6F 74 69 66 79 43 65 6E 74 65 72 41 49 44 4C}
		$c = {6F 6E 52 6F 6F 74 57 6F 72 6B}
		$d = {73 68 75 61 6E 65 74}
	condition:
		$a and $b and $c and $d
}


rule SilverBox_a:Bot
{
	meta:
		description = "This rule detects SilverBox bot Malware"
		sample = "0a5684422fc2ee1bc25882f3d07fef2627948797187c4b4e7554618af2617ac9"
	condition:
		androguard.package_name("com.dyoukbvo.chtdfdwnst") or
		androguard.url("http://49.51.137.120:7878") and
		androguard.permission("android.permission.CHANGE_NETWORK_STATE") and
		androguard.permission("android.permission.DISABLE_KEYGUARD") and
		androguard.permission("android.permission.INTERNET") and
		androguard.permission("android.permission.SEND_SMS") and
		androguard.permission("android.permission.WRITE_SMS") and
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and
		androguard.permission("android.permission.GET_TASKS") and
		androguard.permission("android.permission.READ_CALL_LOG") and
		androguard.permission("android.permission.BROADCAST_PACKAGE_REMOVED") and
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and
		androguard.permission("android.permission.CALL_PHONE") and
		androguard.permission("android.permission.READ_PHONE_STATE") and
		androguard.permission("android.permission.READ_SMS") and
		androguard.permission("android.permission.VIBRATE") and
		androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and
		androguard.permission("android.permission.WAKE_LOCK") and
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and
		androguard.permission("android.permission.RECEIVE_MMS") and
		androguard.permission("android.permission.PACKAGE_USAGE_STATS") and
		androguard.permission("android.permission.CHANGE_WIFI_STATE") and
		androguard.permission("android.permission.RECEIVE_SMS") and
		androguard.permission("android.permission.READ_CONTACTS")
}


rule locker_c: ransomware
{
	meta:
		description = "This rule detects ransomware apps"
		sample = "41764d15479fc502be6f8b40fec15f743aeaa5b4b63790405c26fcfe732749ba"
	condition:
		androguard.package_name("com.simplelocker")
}


rule koodous_y: official
{
	meta:
		description = "Turkish Simpo clicker, sometimes gets on the Google Play"
		sample = "https://koodous.com/apks/25d9c7c7d71c15e505fc866b471dbc59a0a3159828355af7179f96c380709d15"
	strings:
		$a = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67} // setComponentEnabledSetting
		$b = {58 2d 52 65 71 75 65 73 74 65 64 2d 57 69 74 68} // X-Requested-With
		$c = {2e 78 79 7a 2f} // ./xyz
	condition:
		filesize < 300KB and
		$a and
		$b and
		$c		
}


rule SMS_Skunk_a
{
	condition:
		androguard.package_name(/org.skunk/) and
		androguard.permission(/SEND_SMS/)
}


rule SkyMobiVariant_a
{
	meta:
		description = "Variant of Skymobi / SMS Pay / Riskware"
		sample = "80701cf847caf5ddf969ffcdf39144620b3692dc50c91663963a3720ee91e796"
	condition:
 androguard.certificate.sha1("62:71:54:7B:66:8C:E8:81:20:82:49:F8:59:5F:53:15:E3:90:EB:2E")
}
rule SkymobiPorn_a
{
	meta:
		description = "Skymobi variant - Ads / SMS"
		sample = "828e4297a68ced35e16a0bc21e746f7d93c74166104597845bb827709311ceb3"
	strings:
		  $a = "http://121.52.218.66:8011/request_v2.php?"
		  $b = "http://182.92.109.55:10789/userBehaviour/cmcc/mm/single/login?version=1.0.0.7&pid="
		  $c = "http://121.52.218.66:8009/alipayto_v2.php"
		  $d = "http://116.205.4.157:9900/dorecharge3.do"
		  $e = "http://121.52.218.66:8008/request_v2.php"
		  $f = "http://117.135.131.209:808/xiyuerdo/noti_url.php"
		  $g = "http://116.205.4.157:9900/dorecharge2.do"
		  $h = "http://117.135.131.209:808/baidurdo/noti_url.php"
		  $i = "http://111.13.47.76:81/open_gate/web_game_fee.php"
		  $j ="http://118.26.235.115:8080/rdo/services/rdo/shortNotify?channel=$channel&feeCode=$feeCode&schannel=$schannel"
		  $k = "http://182.92.109.55:10789/userBehaviour/cmcc/mm/single/action?version=1.0.0.7&pid="
		  $l ="http://111.13.91.31:12000/feecenter/api/create_order"
		  $m = "http://sms2.upay360.com/geturl.php"
		  $n = "http://111.13.47.76:81/open_gate/web_game_callback.php"
		  $o = "http://121.52.218.66:8012/request_v2.php"
		  $p = "http://182.92.109.55:10789/userBehaviour/cmcc/mm/single/sys?version=1.0.0.7&pid="
		  $q = "http://121.52.218.66:8011/request_v2.php"
		  $r = "http://221.179.131.90/0903?http://111.13.47.76:81/open_gate/web_game_fee.php"
		  $s = "http://121.52.218.66:8009/alipayto_v2.php?"
	condition: 
		any of them 
}


rule SKYMOBI_a
{
	meta:
		description = "Skymobi H"
		sample = "e9562f3ef079bb721d309b77544f83aa5ac0325f03e60dca84c8e041342691f2"
	strings:
		$a = "loadLibrary"
		$b = "assets/libcore.zipPK"
		$c = "assets/libcore2.zipPK"
		$d = "assets/SkyPayInfo.xmlPK"
	condition:
		$a and $b and $c and $d
}


rule SlemBunk_a
{
	meta:
		description = "Rule to detect trojans imitating banks of North America, Eurpope and Asia"
		sample = "4dd4a582071afb3081e8418b5b8178ef7ae256f9d5207c426bf7e5af2933ad20"
		source = "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html"
	strings:
		$a = "#intercept_sms_start"
		$b = "#intercept_sms_stop"
		$c = "#block_numbers"
		$d = "#wipe_data"
		$e = "Visa Electron"
	condition:
		all of them
}


rule Practica4_a
{
	meta:
		description = "Practica4-Slempo"
		sample = "7dab21d4920446027a3742b651e3ef8d"		
	strings:
		$a = "org/slempo/service" 
		$b = "http://185.62.188.32/app/remote/"
		$c = "http://185.62.188.32/app/remote/forms"
		$d = "org.slempo.service"
	condition:
		1 of them
}


rule slempo_a: package
{
	meta:
		description = "This rule detects the slempo (slembunk) variant malwares by using package name and app name comparison"
		sample = "24c95bbafaccc6faa3813e9b7f28facba7445d64a9aa759d0a1f87aa252e8345"
	condition:
		androguard.package_name("org.slempo.service")
}


rule Slempo_a: targeting installed Apps
{
	meta:
		description = "Banker 'Slempo' targeting installed Apps with Overlay"
	strings:
		$command_1 = "#intercept_sms_start"
		$command_2 = "#intercept_sms_stop"
		$command_3 = "#block_numbers"
		$command_4 = "#wipe_data"
		$installedAppsMethod = "getInstalledAppsList"
	condition:
		3 of ($command_*)
		and $installedAppsMethod
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}
rule Slempo_2_a: targeting MastercardData
{
	strings:
		$command_1 = "#intercept_sms_start"
		$command_2 = "#intercept_sms_stop"
		$command_3 = "#block_numbers"
		$command_4 = "#wipe_data"
		$overlay = "mastercard_securecode_logo"
	condition:
		3 of ($command_*)
		and $overlay
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}


rule SLocker_a
{
	meta:
        description = "SLocker variant ransomware gates/IP evidences"
	strings:
		$1 = "adobe/videoprayer/Sms"
   	condition:
		$1 or
    	cuckoo.network.http_get(/pha\?android_version/) or
		cuckoo.network.dns_lookup(/148.251.154.104/)
}
rule SLocker_notifications_a
{
	meta:
        description = "SLocker ransomware notifications"
	strings:
		$1 = { D094D0BED181D182D183D0BF20D0BA20D0B2D0B0D188D0B5D0BCD18320D183D181D182D180D0BED0B9D181D182D0B2D18320D0B2D180D0B5D0BCD0B5D0BDD0BDD0BE20D097D090D091D09BD09ED09AD098D0A0D09ED092D090D09D2C20D0B020D0B2D181D0B520D092D0B0D188D0B820D09BD098D0A7D09DD0ABD09520D094D090D09DD09DD0ABD0952028D0B2D0BAD0BBD18ED187D0B0D18F20D0B4D0B0D0BDD0BDD18BD0B520D0A1D09ED0A6D098D090D09BD0ACD09DD0ABD0A520D181D0B5D182D0B5D0B92C20D0B1D0B0D0BDD0BAD0BED0B2D181D0BAD0B8D18520D0BAD0B0D180D1822920D097D090D0A8D098D0A4D0A0D09ED092D090D09DD09DD0AB20D0B820D09FD095D0A0D095D09DD095D0A1D095D09DD0AB20D0BDD0B020D09DD090D0A820D181D0B5D180D0B2D0B5D180 } //Your phone is locked , and all your personal data
		$2 = { D092D0B2D0B5D0B4D0B8D182D0B520D0BDD0BED0BCD0B5D18020D182D0B5D0BBD0B5D184D0BED0BDD0B0202B33383039373231313436363220D0B820D0BDD0B0D0B6D0BCD0B8D182D0B520D0B4D0B0D0BBD0B5D0B5 } //Enter the phone number 380 972 114 662 and press next
	condition:
		1 of them
}
rule SLocker_cyphers_a
{
	meta:
        description = "SLocker ransomware cyphers"
	strings:
		$A0 = "javax/crypto/Cipher"
		$A1 = "9UDrh3PmFT7utYzJ"
		$A2 = "tb24bOHQ7LIPGip6"
   	condition:
		all of ($A*)
}
rule ZerUnOkLoK_detect_a
{
	meta:
		description = "ZerUnOkLoK, related to SLocker/Ramsomware"
		sample = "7470b65a8c0008c456a235095ea7b1b932b38fe68b3059f48a4b979185030680 from https://koodous.com/apks/4762cf911137d59f615c608e7f344d38b305d9f6843ad540fc376e4ef80af92a"
	strings:
		$a = "ZerUnOkLoK"
	condition:
		$a
}
rule Slocker_components_a
{
	meta:
		sample = "cbf11c080a27986f7583e7838a580bd0f59d5a32ed00717c6d4a6eff58322822"
	strings:
		$1 = "com/android/commonwallsense/LockActivity"
	condition:
		1 of them
}


rule smsBilling_a
{
	meta:
		description = "Sends SMS and connects to remote host."
	strings:
		$a = "http://115.28.56.28:8080/pay/GengYuanSDK.js"
		$b = "http://115.28.56.28:8080/pay/client_bill"
        $c =  "http://115.28.56.28:8080/pay/client_init"
		$d = "http://115.28.56.28:8080/pay/client_mo_lose"
		$e = "http://115.28.56.28:8080/pay/client_pay"
		$f = "http://115.28.56.28:8080/pay/error"
		$g =  "http://115.28.56.28:8080/pay/jarData.jar"
		$h = "http://115.28.56.28:8080/v/clent_confirm"
		$i = "http://115.28.56.28:8080/v/client_key?key="
		$j = "http://115.28.56.28:8080/v/index.jsp"
		$k = "http://121.42.14.182:8080/v/indexs.jsp?v=7"
		$l = "http://121.42.14.182:8080/v/video.jsp"
		$m = "http://192.168.1.158:8080/NetTest/ext.jar"
		$n = "http://blog.sina.com.cn/u/1559825985"
		$u = "http://www.soimsi.com/imsi.html?phone="
	condition:
		any of them
}


rule smsfraud_a
{
	meta:
		description = "This rule detects several sms fraud applications"
		sample = "ab356f0672f370b5e95383bed5a6396d87849d0396559db458a757fbdb1fe495"
    condition:
		cuckoo.network.dns_lookup(/waply\.ru/) or cuckoo.network.dns_lookup(/depositmobi\.com/)
}


rule SMS_Fraud_a
{
	meta:
		Author = "https://www.twitter.com/SadFud75"
	condition:
		androguard.package_name("com.sms.tract") or androguard.package_name("com.system.sms.demo") or androguard.package_name(/com\.maopake/)
}


rule SMSsend_a
{
	meta:
		sample = "cbadcd7d1b99f330665b3fc68d1bdafb5d0a38f36c76505b48b283a2c1bbb48a"
		sample2 = "e3cd70b5ec2fa33d151043d4214ea3ab9623874a45ae04cc0816ebf787c045ff"
		sample3 = "cc21dc0d3b09a47f008cd68a3c7086f0112c93a027b18ed4283541182d0dfc13"
	strings:
		$a = "SHA1-Digest: ZEVCPDHNa58Z+ad4DBPhHzHs2Q0="
		$b = "5148cfbb-cd66-447b-a3dc-f0b4e416d152"
		$c = "merchantOrderTime"
		$d = "dialog_content_l"
	condition:
		all of them
}
rule SMSSend2_b
{
	meta:
		sample = "5e5645bfc4fa8d539ef9ef79066dab1d98fdeab81ac26774e65b1c92f437b5b7"
		sample2 = "bf1529540c3882c2dfa442e9b158e5cc00e52b5cf5baa4c20c4bdce0f1bb0a6f"
		sample3 = "0deb55c719b4104ba1715da20efbc30e8f82cbff7da4d4c00837428e6dc11a24"
	strings:
		$a = "unicom_closepress"
		$b = "UpDownArrow=02195"
		$c = "SHA1-Digest: yMpAl55vjxeiLiY1ZwkqDUztpfg="
		$d = "&&res/drawable-xhdpi/hfb_btn_normal2.png"
	condition:
		all of them
}


rule boibaSender_a
{
	meta:
		description = "Collects info and sends SMS to contacts. Usually faking Candy Crush"
	strings:
		$a = "http://vinaaz.net/check/game.txt"
		$b = "http://192.168.1.12:8080/BoiBaiServer/services/BoiBaiTayRemoteImpl"
		$c = "http://sms_service/boibaitay/"
	condition:
		$a or $b or $c
}


rule smsfraud_b
{
	meta:
		description = "This rule detects a kind of SMSFraud trojan"
		sample = "265890c3765d9698091e347f5fcdcf1aba24c605613916820cc62011a5423df2"
		sample2 = "112b61c778d014088b89ace5e561eb75631a35b21c64254e32d506379afc344c"
	strings:
		$a = "E!QQAZXS"
		$b = "__exidx_end"
		$c = "res/layout/notify_apkinstall.xmlPK"
	condition:
		all of them
}
rule smsfraud2_a {
        meta:
                sample = "0200a454f0de2574db0b58421ea83f0f340bc6e0b0a051fe943fdfc55fea305b"
                sample2 = "bff3881a8096398b2ded8717b6ce1b86a823e307c919916ab792a13f2f5333b6"
        strings:
                $a = "pluginSMS_decrypt"
                $b = "pluginSMS_encrypt"
                $c = "__dso_handle"
                $d = "lib/armeabi/libmylib.soUT"
                $e = "]Diok\"3|"
        condition:
                all of them
}


rule nang_a
{
	meta:
		description = "Little and simple SMSFraud"
		sample = "8f1ee5c8e529ed721c9a8e0d5546be48c2bbc0c8c50a84fbd1b7a96831892551"
	strings:
		$a = "NANG"
		$b = "deliveredPI"
		$c = "totalsms.txt"
	condition:
		all of them
}


rule smsfraud_c
{
	meta:
		sample = "7ea9a489080fa667b90fb454b86589ac8b018c310699169b615aabd5a0f066a8"
		search = "cert:14872DA007AA49E5A17BE6827FD1EB5AC6B52795"
	condition:
		androguard.certificate.sha1("14872DA007AA49E5A17BE6827FD1EB5AC6B52795")
}
rule smsfraud2_b {
	strings:
		$a = "isUserAMonkey" 
		$b = "android.permission.CHANGE_CONFIGURATION" wide ascii
		$c = "%android.permission.MODIFY_PHONE_STATE" wide ascii
		$d = "+android.permission.SEND_SMS_NO_CONFIRMATION" wide ascii
		$e = "&android.permission.PACKAGE_USAGE_STATS" wide ascii
		$f = "Obfuscator-clang version 3.4 (tags/RELEASE_34/final) (based on LLVM 3.4svn)"
		$g = "res/layout/authenticator.xml" wide ascii
		$h = "eQdPXV^QZ"
		$i = "my_transparent"
		$j = "android.intent.action.DATE_CHANGED" wide ascii
		$k = "Gxq3/70q/>7q;>*/:+<<1<p>6>"
		$l = "__modsi3"
		$m = "MService.java"
	condition:
		all of them
}


rule simplerule_a
{
	meta:
		description = "This rule detects a SMS Fraud malware"
		sample = "4ff3169cd0dc6948143bd41cf3435f95990d74538913d8efd784816f92957b85"
	condition:
		androguard.package_name("com.hsgame.hmjsyxzz") or 
		androguard.certificate.sha1("4ECEF2C529A2473C19211F562D7246CABD7DD21A")
}


rule smsfraud_d
{
	meta:
		description = "This rule detects apks related with sms fraud"
		sample = "79b35a99f16de6912d6193f06361ac8bb75ea3a067f3dbc1df055418824f813c"
	condition:
		androguard.certificate.sha1("1B70B4850F862ED0D5D495EC70CA133A4598C007")
}


rule SMSFraud_a: chinese
{
	meta:
		description = "Simulate apps with chinese name to make sms fraud."
		sample = "64f4357235978f15e4da5fa8514393cf9e81fc33df9faa8ca9b37eef2aaaaaf7"
	condition:
		androguard.certificate.sha1("24C0F2D7A3178A5531C73C0993A467BE1A4AF094")
}


rule SMSFraud_b: russian_dev
{
	meta:
		sample = "f9a86f8a345dd88f87efe51fef3eb32a7631b6c56cbbe019faa114f2d2e9a3ac"
	condition:
		androguard.certificate.sha1("7E209CBB95787A9F4E37ED943E8349087859DA73") or
		androguard.certificate.sha1("3D725C7115302C206ABDD0DA85D67AD546E4A076") or
		androguard.certificate.sha1("AC2D0CFAB11A82705908B88F57854F721C7D2E4E") or
		androguard.certificate.sha1("F394D49E025FA95C38394BB05B26E6CAB9DF0A85") or
		androguard.certificate.sha1("224DE2C3B80A52C08B24A0594EDD6C0A0A14F0D2") or
		androguard.certificate.sha1("CF240D24D441F0A2808E6E5A0203AC05ACF0D10C")
}


rule SMSFraud_c
{
	condition:
		androguard.certificate.issuer(/\/C=UK\/ST=Portland\/L=Portland\/O=Whiskey co\/OU=Whiskey co\/CN=John Walker/)
}


rule SmsFraudUsingURLsAndDNS_a: smsfraud
{
	meta:
		description = "This rule should match applications that send SMS"
		inspired_by = "https://koodous.com/rulesets/3047"
	condition:
		androguard.url("app.tbjyz.com")
		or androguard.url("tools.zhxapp.com")
		or cuckoo.network.dns_lookup(/app\.tbjyz\.com/)
		or cuckoo.network.dns_lookup(/tools\.zhxapp\.com/)
}


rule smspay_a
{
	meta:
		description = "This rule detects smspay trojans"
		sample = "d68e86edd71003e3e64954b0de1ecf225d5bf7bea910010b18c3c70b2482174e"
	strings:
		$a = "Lcom/hz/mama/u;"
		$b = "hjwg16Y0G83C18H9wpMLWi25KDSLyNLA2I509GQ5wydMj2qRYVHjf9fV7Xl9cfcFstlYsOtRAxdUcMOa0nkO1qhsbeEqirQRJmnW0Yub6Yar1FzfWJTlHutV43HJmd8E"
		$c = ", signKey="
		$d = ", sample="
	condition:
		all of them
}


rule SMSPay_a
{
	meta:
		description = "This rule detects SMSPay apps"
		sample = "32e322cb0f2e39a6ddc2a9671f262e9f0e3160255710acd6769cb3edf515f36f"
	strings:
		$a = "To activate the application, you must allow the sending of a query using short numbers. For complete information on pricing can be found at the web site: http://www.mobi911.ru/" ascii wide
	condition:
		$a
}
rule SMSPay2_a
{
	meta:
		sample = "4f75890ff99ff8e94b6f7f4b33f9c21d482b2dffb78ced72484acb74e14bb2e7"
	condition:
		androguard.certificate.sha1("6818663E1B038E42D7B8CBCF63CF3D470DA90124")
}


rule SMSPay_b: chinese_porn
{
	meta:
		description = "This rule detects the SMSPay apps"
		sample = "e0fcfe3cc43e613ec733c30511492918029c6c76afe8e9dfb3b644077c77611a"
	condition:
		androguard.certificate.sha1("42867A29DCD05B048DBB5C582F39F8612A2E21CD")
}


rule smsPaym_a
{
	meta:
		description = "AppSMSPayLog.aspx always returning true when no payment was done. Getting user to pay through SMS"
	strings:
		$a = "http://msg-web.pw:8456/msg/"
		$b = "http://221.12.6.198:8010/APP/AppSMSPayLog.aspx"
		$c = "http://221.12.6.198:8010"
	condition:
		$a or $b or $c
}


rule SMSReviever_a: banker
{
	meta:
		description = "To found apps with a typo error, is classified too as ibanking"
		sample = "6903ce617a12e2a74a3572891e1df11e5d831632fae075fa20c96210d9dcd507"
	strings:
	$a = {53 6D 73 52 65 63 69 65 76 65 72 75 70 64 61 74 65} //SmsRevieverupdate
	condition:
		$a
}


rule smsreg_a
{
	meta:
		description = "SMSReg"
		sample = "f861d78cc7a0bb10f4a35268003f8e0af810a888c31483d8896dfd324e7adc39"
	strings:
		$a = {F0 62 98 9E C7 52 A6 26 92 AB C1 31 63}
	condition:
		all of them
}


rule SMSReg_a
{
	meta:
		description = "This rule detects SMSReg trojan"
		sample = "b9fd81ecf129d4d9770868d7a075ba3351dca784f9df8a41139014654b62751e"
	strings:
		$a = "before send msg to cu server optaddr"
		$b = "Service destory"
		$c = "Enter start service"
		$d = "The sim card in this phone is not registered, need register"
	condition:
		all of them
}


rule smsreg_b
{
	meta:
		sample = "1c2e1083f9c73a222af21351b243d5072fcc3360a5be6fa4d874e4a94249a68d"
		search = "package_name:com.dnstore.vn"
	strings:
		$a = "var msg2_4 = \"DSD zombie\";"
		$b = "Ldnteam/gamevui2014/net/ScriptInterface$Downloader3"
	condition:
		($a and $b) or androguard.package_name("com.dnstore.vn")
}


rule SMSReg_b
{
        meta:
                description = "This rule detects SMSReg apps"
                sample = "ed3c5d4a471ee4bf751af4b846645efdeafcdd5f85c1f3bdc58b84119b7d60e8"
				packagename = "com.sm.a36video1"
        strings:
                $a = "kFZFZUIF"
                $b = "btn_title_shop"
                $c = "more_about_version" wide
                $d = "$on}$fxfThjfnyj$hdembl;"
                $e = "ad_video_vip" wide
        condition:
                all of them
}


rule SMSRegister_a
{
	meta:
		description = "This rule detects applications that register sms and send"
		sample = "ec488970bf7152726220ab75f83f8aaa48d824d942fb94ef52a64b6901f48274"
		sample2 = "ed73113b63325d5060f0d39a827bc32281e005c1de8d9dbea2cd583358382870"
		sample3 = "ec4c23a0eba77f68e88e331bc3b88162a18c5c27677858d8698ba8a47a564b37"
	strings:
		$key = "\"cmd_key\":\"DJ_jh_2\""
		$ip = "182.92.21.219:10789"
		$number1 = "{\"NUM\":\"10086\"}"
		$number2 = "{\"NUM\":\"10665110\"}"
		$number3 = "{\"NUM\":\"11185*\"}"
		$number4 = "{\"NUM\":\"12110*\"}"
		$number5 = "{\"NUM\":\"12114*\"}"
		$number6 = "{\"NUM\":\"123??\"}"
		$number7 = "{\"NUM\":\"12520*\"}"
		$number8 = "{\"NUM\":\"13800138000\"}"
		$number9 = "{\"NUM\":\"7022288\"}"
		$number10 = "{\"NUM\":\"955*\"}"
	condition:
		($key and $ip) and (any of ($number*))
}


rule SMSSend_b
{
	meta:
		description = "This rule detects applications that send SMSs"
		sample = "ee95d232e73ba60cbe31dbae820c13789b5583b1b972df01db24d2d2159446d7"
	strings:
		$a = "\" cmcc = \"21\" cuc = \"50\" cnc = \"\">20</province>" wide ascii
		$b = "\" cmcc = \"10\" cuc = \"36\" cnc = \"\">19</province>" wide ascii
		$key_file = "assets/keycode.txtbinlangPK"
	condition:
		any of them
}


rule smssend_a
{
	meta:
		description = "This rule detects smssend trojan"
		sample = "fcfe5c16b96345c0437418565dbf9c09e9e97c266c48a3b04c8b947a80a6e6c3"
	strings:
		$a = "generatesecond"
		$b = "res/layout/notification_download_finished.xml"
		$c = "m_daemonservice"
		$d = "((C)NokiaE5-00/SymbianOS/9.1 Series60/3.0"
		$e = "respack.tar"
	condition:
		all of them
}


rule smssend_b:fakeins
{
	meta:
		sample = "04531241e81c7d928e7bc42b049eb0b4f62ecd1a1c516051893ba1167467354c"
	condition:
		androguard.certificate.sha1("405E03DF2194D1BC0DDBFF8057F634B5C40CC2BD")
}
rule smssend2_a:fakeins
{
	meta:
		sample = "2edf40289ee591e658730f6d21538729e0e3e1c832ae76acf207d449cfa91979"
		sample2 = "9378c6c10454b958384e0832a45eb37b58e725528e13bee1e3efe585e18e016a"
		sample3 = "4650d0f08dc2fa69516906b44119361b3cdcab429301aa5f16c7b8bfd95069c3"
	strings:
		$a = "SHA1-Digest: flyZ6fARO6a2PCu0CLg0cZExbNo="
		$b = "<br/>9800 - 296.61 RUR"
		$c = "<br/>3352 - 90.00 RUR"
	condition:
		all of them
}


rule SMSSender_a
{
	meta:
		description = "This rule detects a type of SMSSender"
		sample = "96d449f5073bd7aaf50e06a6ed1eb2ed0afaca3ed60581c5c838aa7119fb0e97"
		search = "package_name:com.nys.mm"
	strings:
		$url1 = "http://117.79.227.178:9991"
		$url2 = "http://172.17.236.157:8082/app/mobile/json"
		$json = "\"tn\":\"%s\",\"user\":\"%s\",\"locale\":\"%s\",\"terminal_version\":\"%s\""
		$fail_message = "Fail to construct message"
	condition:
		all of them
}
rule SMSSender2_a
{
	meta:
		description = "This rule detects another type of SMSSender"
		sample = "a653bd23569aadf02a2202c9a75e83af1263297fbac8cdd14ef4c83426bdc145"
	strings:
		$string_1 = "470,471,472,473,474,475,476,477,478,479,482,483"
		$string_2 = "890,898,899"
		$string_3 = "029,910,911,912,913,914,915,916,917,919"
		$characteristic = "notniva=0220C"
		$icon_name = "mili_smspay_close.png"
	condition:
		all of them
}


rule smssender_FakeAPP_a
{
	condition:
		androguard.certificate.sha1("405E03DF2194D1BC0DDBFF8057F634B5C40CC2BD") or 
		androguard.package_name("test.app") or 
		androguard.receiver("b93478b8cdba429894e2a63b70766f91.ads.Receiver")
}
rule SMSFraud_d
{
	condition:
		androguard.certificate.sha1("003274316DF850853687A26FCA9569A916D226A0") or 
		androguard.package_name("com.googleapi.cover") or 
		androguard.package_name("ru.android.apps")
}


rule smsSender_b
{
	meta:
		description = "Sends SMS. Final number is obfuscated, but easy to read. Code below."
	strings:
		$mfprice = "236"
		$price2 = "94.70"
	condition:
		androguard.package_name("com.software.application") and ($mfprice or $price2)
}


rule smsspy_a
{
	meta:
		description = "This rule detects SMSSpy from Korea"
		sample = "ed1541efb7052dfe76e5e17338d68b291d68e9115e33e28b326dc4b63c7bfded"
	strings:
		$a = "getBodyParts"
		$b = "audioMode"
		$c = "InsertContacts"
		$d = "where cnt_phone="
		$e = "CallStateReceiver.java"
		$f = "CallBlock"
		$g = "set cnt_block="
		$h = "cnt_mail text"
		$i = "bSMSBlockState"
		$j = "cnt_phone text"
		$k = "getsmsblockstate.php?telnum="
	condition:
		all of them
}


rule Trojan_c: SMSSpy
{
	meta:
		description = "This rule detects the dropper of a trojan that steal SMS"
		sample = "c2b672fdde5e141b8db513a30b8254b9434f0eef4f0c92a55988347a20934206"
	strings:
		$trojanapp = "android.system.apk"
		$trojanservice = "com.android.system.MyService"
	condition:
		$trojanapp and
		$trojanservice
}


rule sms_fraud_a: MSACM32
{
	meta:
		description = "sms-fraud examples"
		sample = "8b9cabd2dafbba57bc35a19b83bf6027d778f3b247e27262ced618e031f9ca3d c52112b45164b37feeb81e0b5c4fcbbed3cfce9a2782a2a5001fb37cfb41e993"
	strings:
		$string_a = "MSACM32.dll"
		$string_b = "android.provider.Telephony.SMS_RECEIVED"
		$string_c = "MAIN_TEXT_TAG"
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.SEND_SMS/)
}
rule sms_fraud_gen_a: generic
{
	meta:
		description = "This is just an example"
		thread_level = 3
		in_the_wild = true
	strings:
		$a = "080229013346Z"
		$c = "350717013346Z0"
		$b = "NUMBER_CHAR_EXP_SIGN"
	condition:
		$a and $b and $c and
		androguard.permission(/android.permission.SEND_SMS/)
}


rule sppromo_fakeapps_a
{
	meta:
		description = "Detects few shopping related apps which redirect to a malicious website"
	strings:
		$a_1 = "mobilpakket/MainActivity"
		$a_2 = "http://sppromo.ru/apps.php?"
	condition:
		all of ($a_*)
}


rule wefleet_a
{
	strings:
		$a = "wefleet.net/smstracker/ads.php" nocase
	condition:
		$a
}


rule Twittre_a
{
    condition:
        androguard.certificate.sha1("CEEF7C87AA109CB678FBAE9CB22509BD7663CB6E") and not
		androguard.certificate.sha1("40F3166BB567D3144BCA7DA466BB948B782270EA") //original
}


rule urls_a
{
	meta:
		description = "Lukas Stefanko https://twitter.com/LukasStefanko/status/877842943142281216"
	strings:
		$ = "0s.nrxwo2lo.ozvs4y3pnu.cmle.ru"
		$ = "0s.nu.ozvs4y3pnu.cmle.ru"
		$ = "0s.nu.n5vs44tv.cmle.ru"
		$ = "navidtwobottt.000webhostapp.com/rat/upload_file.php"
		$ = "telememberapp.ir/rat/upload_file.php"
	condition:
		1 of them
}


rule spynote_a: RAT
{
	meta:
		sample = "bd3269ec0d8e0fc2fbb8f01584a7f5de320a49dfb6a8cc60119ad00c7c0356a5"
	condition:
		androguard.package_name("com.spynote.software.stubspynote")
}


rule Trojan_Spynote_a
{
    meta:
		author = "https://twitter.com/SadFud75"
        description = "Yara rule for detection of SpyNote"
    strings:
        $cond_1 = "SERVER_IP" nocase
        $cond_2 = "SERVER_NAME" nocase
        $cond_3 = "content://sms/inbox"
        $cond_4 = "screamHacker" 
    condition:
        all of ($cond_*)
}


rule Spynote_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$b_1 = "screamHacker"
	condition:
		any of ($b_*)
}


rule spynote4_a
{
	meta:
		description = "Yara rule for detection of  Spynote4.0"
		author = "invoker"
	strings:
		$str_1 = "scream" 
	condition:
		androguard.package_name("system.operating.dominance.proj") and 
		all of ($str_*)
}


rule subscript_a
{
	meta:
		description = "Coonecting to one of those sites (Splitting ',') and getting the user into a subscription."
	strings:
		$a = "fapecalijobutaka.biz,ymokymakyfe.biz,kugoheba.biz"
	condition:
		$a 
}


rule suidext_a: official
{
	meta:
		description = "detect suid"
	strings:
		$a = {50 40 2d 40 55 53 5e 2d}
	condition:
		$a
}


rule PUA_a: Untrusted_Cert
{
    condition:
        androguard.certificate.sha1("7E1119BBD05DE6D0CBCFDC298CD282984D4D5CE6") or
       	androguard.certificate.sha1("DEF68058274368D8F3487B2028E4A526E70E459E")
}
rule Suspect_a
{
	strings: 
		$ = "tppy.ynrlzy.cn"
	condition:
		1 of them
}


rule svpeng_a
{
	meta:
		description = "Trojan-Banker.AndroidOS.Svpeng"
		sample = "62aaff01aef5b67637676d79e8ec40294b15d6887d9bce01b11c6ba687419302"
	condition:
		androguard.receiver("com.up.net.PoPoPo") or
		androguard.receiver("com.up.net.PusyCat")
}
rule svpeng2_a
{
	strings:
		$= "http://217.182.174.92/jack.zip"
	condition:
		all of them
}


rule syringe_a
{
	strings:
		$a = "setHostService"
		$b = "getHostActivity"
		$c = "MainApplication.java"
		$d = "kqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwqAFW0sDGPfZ9GxASIFGcdrCdHefFdCjmB4c5M9RADKikKYlD9LjjlTtcTfP6MBMUGayzgDAI0Tt4oqLI1//DddfIFCQ4eC2VTYiTsb+dx23GT5wERpaN2T+1cbZG9aNL2TEkriuoN2ovIa6yXGMI8srqjlq9TP8djedzgRaStQl/zrjPz+G00FxfBObgfgTvzgaAvaluBXTnvu0N2t5KG0ubQC24d2dTrr+Kc9Y9ZiMqDTOn8rLgoM/PcJZkKg5d7GQMpNC1GJeWCcGh6NMhv3QGn/GswfW865AmyxL75JE+61Un8cxouTUQzEsGZ3zNR/F3tA0SKyQCl7LwfV8dwIDAQ"
	condition:
		all of them
}


rule koodous_z: official
{
	meta:
		description = "http://researchcenter.paloaltonetworks.com/2015/10/chinese-taomike-monetization-library-steals-sms-messages/"
	condition:
		androguard.url("http://112.126.69.51/2c.php")
}


rule TeleRAT_a
{
	meta:
		author = "R"
		description = "https://researchcenter.paloaltonetworks.com/2018/03/unit42-telerat-another-android-trojan-leveraging-telegrams-bot-api-to-target-iranian-users/"
	condition:
		androguard.activity(/getlastsms/i) and
		(androguard.service(/botrat/i) or androguard.service(/teleser/i))
}


rule tinhvan_a
{
	meta:
		sample = "0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5"
	condition:
		androguard.certificate.sha1("0DFBBDB7735517748C3DEF3B6DEC2A800182D1D5")
}


rule Tordow2_a
{
	meta:
		description = "This rule detects tordow v2.0"
		sample = "37ece331857dc880b55ce842a8e01a1af79046a919e028c2e4e12cf962994514"
		report = "https://blog.comodo.com/comodo-news/comodo-warns-android-users-of-tordow-v2-0-outbreak/"
	strings:
		$a = "http://5.45.70.34/error_page.php"
		$b = "http://5.45.70.34/cryptocomponent.1"
	condition:
		androguard.url("http://5.45.70.34") or ( $a and $b)
}
rule RelatedtoTordow_a
{
	meta:
		description = "This rule detects apps related , from same serial certificate"
		sample = "ae645ea25450cdbd19d72831a387f0c20523e6d62d201561ee59949b3806a82c"
	condition:
		androguard.url("http://185.117.72.17") 
}
rule SameCertificate_a
{
	meta:
		description = "Same certificate that first samples"
	condition:
		androguard.certificate.sha1("0B7C3BC97B6D7C228F456304F5E1B75797B7265E")
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.
	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
rule Android_Triada_a: android
{
	meta:
		author = "reverseShell - https://twitter.com/JReyCastro"
		date = "2016/03/04"
		description = "This rule try to detects Android.Triada.Malware"
		sample = "4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b"
		source = "https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/"
	strings:
		$string_1 = "android/system/PopReceiver"
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.GET_TASKS/)
}


rule koodous_{: official
{
	meta:
		description = "Triada token(https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/)"
		sample = "0cc9bcf8ae60a65f913ace40fd83648e"
	strings:
		$a = {63 6f 6e 66 69 67 6f 70 62}
	condition:
		$a
}


rule facebookopt_a: banker
{
	meta:
		description = "Android Spy Banker"
		sample = "562da283fab7881ea4fa8ce5d764720d8d87e167cc9bb797a48e7a53a5314fae"
	condition:
		androguard.permission(/android.permission.SEND_SMS/)
		and androguard.permission(/android.permission.CALL_PHONE/)
		and androguard.certificate.sha1("BF0DE1B54673F2092FDC5A75DA4FFC26F65E1602")
}


rule Trojan_Banker_Marcher_a {
	meta:
	description = "Trojan-Banker targeting Erste Bank Austria, and many others (Marcher)"
	strings:
		$ = "17817363627@163.com"
		$ = "SHA1-Digest: 0lCO/Q8bPDm8SyrRcp46Kx+4NPg="
		$ = "SHA1-Digest: MzBgnoodgsYtDvNxEGMil4Ypklk="
		$ = "ac-ab.cc"
		$ = "appp-world.at"
		$ = "appppp.at"
		$ = "appsecure57703.cc"
		$ = "appsecure57704.cc"
		$ = "appsecure57705.cc"
		$ = "austriaservices.cc"
		$ = "casserver-login.php"
		$ = "erste-sicherheitszertifkat.eu"
		$ = "erste-sicherheitszertifkat.in"
		$ = "servicesupdaters.com"
		$ = "servicesupdaterss.com"
		$ = "serviceupdates.cc"
		$ = "world-appp.at"
		$ = "xerography.cc"
		$ = "chudresex.at"
		$ = "coxybajau.net"
		$ = "limboswosh.com"
		$ = "memosigla.su"
		$ = "mulsearyl.ru"
		$ = "pishorle.net"
		$ = "sarahtame.at"
		$ = "sarahtame.cc"
		$ = "curlyhair.at"
        $ = "bushyhair.at"
        $ = "pound-sterling-update.at"
		$ = "ldfghvcxsadfgr.at"
		$ = "securitybitches3.at"
		$ = "weituweritoiwetzer.at"
		$ = "securitybitches1.at"
		$ = "securitybitches2.at"
		$ = "wqetwertwertwerxcvbxcv.at"
		$ = "polo777555lolo.at"
		$ = "polo569noso.at"
		$ = "wahamer8lol77j.at"
		$ = "trackgoogle.at"
		$ = "track-google.at"
	condition:
	1 of them and not androguard.package_name(/deebrowser/)
}
rule Trojan_Banker_Marcher2_a {
	meta:
	description = "Trojan-Banker targeting Erste Bank Austria, and many others (Marcher)"
	strings:
		$a = "Name: res/raw/blfs.key"
		$b = "Name: res/raw/config.cfg"
	condition:
	all of them
}


rule Trojan_Banker_a:Marcher {
	strings:
		$ = "Landroid/telephony/SmsManager"
		$ = "szClassname"
		$ = "szICCONSEND"
		$ = "szModuleSmsStatus"
		$ = "szModuleSmsStatusId"
		$ = "szName"
		$ = "szNomer"
		$ = "szNum"
		$ = "szOk"
		$ = "szTel"
		$ = "szText"
		$ = "szpkgname"
	condition:
		all of them
}


rule Trojan_Banker4_a:Marcher {
	strings:
		$ = "a!v!g.!a!n!t!i!vi!ru!s"
		$ = "a!vg!.!a!n!t!i!v!i!r!u!s"
		$ = "a!vg!.an!ti!vi!r!us!"
		$ = "a!vg.a!n!t!i!v!irus!"
		$ = "av!g!.!a!n!ti!v!i!r!us"
		$ = "av!g.!an!ti!v!i!ru!s!"
		$ = "a!vg.!a!nt!i!v!irus"
		$ = "avg!.!a!n!tivi!ru!s!"
		$ = "avg.!a!n!t!i!v!i!r!u!s"
		$ = "a!v!g.a!n!tiv!i!ru!s"
	condition:
		1 of ($)
}


rule Trojan_Banker_Slempo_a
{
	meta:
		description = "Trojan-Banker.Slempo"
		sample = "349baca0a31753fd8ad4122100410ee9"
	strings:
		$a = "org/slempo/service" nocase
		$b = /com.slempo.service/ nocase
		$c = "com/slempo/baseapp/Service" nocase
		$d = "org/slempo/baseapp/Service" nocase
	condition:
		1 of them
}


rule Finsky_a {
	meta:
	sample = "f10ff63c0a8b7a102d6ff8b4e4638edb8512f772,a5b9ca61c2c5a3b283ad56c61497df155d47f276"
	description = "http://vms.drweb.ru/virus/?_is=1&i=14891022"
	strings:
		$hooker1 = "hooker.dex"
		$hooker2 = "hooker.so"
		$wzh = "wzhtest1987"
		$finsky = "finsky"
		$cc = "api.sgccrsapi.com"
	condition:
		1 of ($hooker*) and ($cc or $wzh) and $finsky
}


rule GCM_a
{
	meta:
		description = "Trojan-SMS AndroidOS GCM"
		sample = "81BB2E0AF861C02EEAD41FFD1F08A85D9490FE158586FA8509A0527BD5835B30"
	strings:
		$a = "whatisthefuckingshirtmazafakayoyonigacomon.ru"
	condition:
		all of them
}


rule Trojan_Switcher_a {
	meta:
	sample = "d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150"
	description = "https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/"
	strings:
		$dns1 = "101.200.147.153"
		$dns2 = "112.33.13.11"
		$dns3 = "120.76.249.59"
		$account1 = "admin:00000000@"
		$account2 = "admin:000000@"
		$account3 = "admin:0123456789@"
		$account4 = "admin:110110@"
		$account5 = "admin:110120@"
		$account6 = "admin:1111111@"
		$account7 = "admin:111111@"
		$account8 = "admin:11223344@"
		$account9 = "admin:112233@"
		$account10= " admin:123123123@"
		$account11= " admin:123123@"
		$account12= " admin:1234567890@"
		$account13= " admin:123456789@"
		$account14= " admin:123456789a@"
		$account15= " admin:12345678@"
		$account16= " admin:123456@"
		$account17= " admin:147258369@"
		$account18= " admin:5201314@"
		$account19= " admin:520520@" 
		$account20= " admin:66666666@"
		$account21= " admin:666666@"
		$account22= " admin:66668888@"
		$account23= " admin:789456123@"
		$account24= " admin:87654321@"
		$account25= " admin:88888888@"
		$account26= " admin:888888@"
		$account27= " admin:987654321@"
		$account28= " admin:admin@" 
	condition:
		1 of ($dns*) and 2 of ($account*)
}


rule Click415to417_a
{
	strings:
	 $ = "http://apk-archive.ru"
	 $ = "aHR0cDovL2Fway1hcmNoaXZlLnJ1L2dvb2dsZXBsYXlhcHBzL2NoZWNrL281L2luZGV4LnBocD9pbXNpPQ"
	condition:
		androguard.url(/apk-archive.ru/i)
		or 
		1 of them
}


rule RootNik_a {
	meta:
	description = "https://blog.fortinet.com/2017/01/26/deep-analysis-of-android-rootnik-malware-using-advanced-anti-debug-and-anti-hook-part-ii-analysis-of-the-scope-of-java"
	strings:
		$ = "grs.gowdsy.com"
		$ = "gt.rogsob.com"
		$ = "gt.yepodjr.com"
		$ = "qj.hoyebs.com"
		$ = "qj.hoyow.com"
	condition:
		1 of them
}


rule trojanSMS_a
{
	meta:
		description = "This rule detects trojan SMS"
		sample = "ff8ccead81eca2154cf9e891e15f52c8a154ea3aba5e62498b11fb843135837f"
		source = "http://pastebin.com/rLPux7ts"
	strings:
		$a = "sendMultipartTextMessage"
		$b = "l68g66qypPs="
		$c = "MY7WPp+JQGc="
		$d = "com.android.install"
	condition:
		all of them
}


rule commasterclean_a
{
	strings:
		$d1 = "kstest.8rln3ufc.pw"
		$d2 = "newappsdk.fbvxi8mz.pw"
		$d3 = "newstr.pkw9tq2v.pw"
		$d4 = "sscapi.goytd2by.pw"
		$d5 = "ks.urva3ucp.pw"
		$d6 = "app.urva3ucp.pw"
		$d7 = "newstrapi.pkw9tq2v.pw"
		$d8 = "newapi.fbvxi8mz.pw"
		$ip = "52.199.190.161"
		$c = "eu/chainfire/libsuperuser/HideOverlaysReceiver"
		$s0 = "com.master.clean.relate.CrkService"
		$s1 = "com.master.clean.relate.FcService"
		$s2 = "com.master.clean.relate.PoniService"
		$s3 = "com.master.clean.relate.ScreenServer"
		$s4 = "com.master.clean.relate.SjkJobService"
	condition:
		(1 of ($d*) or $ip ) or
		($c and 3 of ($s*))
}
rule CleanupRadar_a
{
	condition:
	androguard.package_name("com.Airie.CleanupRadar")
}


rule TwoFaStealer_a
{
	meta:
		sample = "126547985987c3ecb1321a3a565d8565b64d437fd28418a6ba4bbc3220f684d2"
		description = "This rule detects samples that steal 2fa from the notifications"
		blog = "https://www.welivesecurity.com/2019/06/17/malware-google-permissions-2fa-bypass/"
	strings:
		$a1 = "code_servise"
        $a2 = "code_maiin"
        $a3 = "coin"
        $a4 = "ACTION_NOTIFICATION_LISTENER_SETTINGS"
	condition:
		all of ($a*)
}


rule unknown_b:agent
{
	meta:
		description = "This rule detects a new malware family that is under study"
		sample = "405314192f39a587a1f87b1599fcd12cf1387d65b96ce3a857baaf7863420ef7"
		sample2 = "4913737c1bfa69a01e8b03dd31b90735657cd331a415f507b0e87dd4f1715cb2"
		sample3 = "52de577ce4ce1b078cb4963a73aa88a07e99b4c3e8e33474c59ed6e77741eef2"
	strings:
		$a = "ShellReceiver.onReceive()"
		$b = "Lcom/sns/e/bi;"
		$c = "W5M0MpCehiHzreSzNTczkc9d"
	condition:
		all of them
}


rule vidroid_a
{
	meta:
		description = "This rule detects vidroid malware"
		sample = "855c40a5bc565fc16a6293757f822fbe1abc82708974046e940fd71230b1df32"
	strings:
		$a = "Mozilla/5.0 (Linux; U; {app_id}; {android_version}; de-ch; Vid4Droid) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30"
		$b = "Lcom/vid4droid/PleechActivity$MyChromeWebViewClient;"
	condition:
		androguard.package_name("com.vid4droid") or 
		($a and $b) 
}


rule VKSteal_a: official
{
	meta:
		description = "This rule detects vK login stealer"
		info = "https://securelist.com/blog/incidents/72458/stealing-to-the-sound-of-music/"
	strings:
		$a = {2F 61 70 2F 3F 6C 3D 25 73 26 70 3D 25 73}
		$b = {2F 73 70 6F 6E 73 6F 72 5F 67 72 6F 75 70 73 2E 74 78 74}
		$c = {63 61 70 74 63 68 61 5F 69 6D 67 3D}
		$d = {70 68 6F 74 6F 5F 31 30 30}
		$e = {75 73 65 72 5F 64 6F 77 6E 6C 6F 61 64 65 64 5F 63 6F 75 6E}
	condition:
		$a and $b and $c and $d and $e
}


rule volcman_dropper_a
{
	meta:
		description = "Dropper"
		sample = "322dfa1768aac534989acba5834fae4133177fec2f1f789d9a369ebbf1f00219"
		certificate = "8AA6F363736B79F51FB7CF3ACFC75D80F051325F"
	condition:
		cuckoo.network.dns_lookup(/advolcman\.com/)
		or cuckoo.network.dns_lookup(/woltrezmhapplemouse\.com/)
		or cuckoo.network.dns_lookup(/aerovolcman\.com/)
}


rule wait_for_the_police_a: official
{
	meta:
		description = "This rule detects apps created by GYM that are SMS-frauds but looks like ramsomware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "iiAttention, you are trying to commit a crime. Please wait while a police car goes to your position. thanks"
		$b = " intentando cometer un delito, por favor, espere mientras un coche patrulla se dirige a su posici"
	condition:
		androguard.certificate.issuer(/GYM/) and 
		androguard.certificate.sha1("55C1FB97AC36FCCEC1175CF06DAA73214B23054F") and
		($a or $b)
}


rule WapCash_a: official
{
	meta:
		description = "This rule detects samples fom WapCash developer"
		sample = "00d0dd7077feb4fea623bed97bb54238f2cd836314a8900f40d342ccf83f7c84"
	condition:
		androguard.certificate.sha1("804B1FED90432E8BA852D85C7FD014851C97F9CE")
}


rule WhatsAppGold_a
{
	meta:
		description = "Rule to detect WhatsApp Gold"
		sample = "26fe32f823c9981cb04b9898a781c5cdf7979d79b7fdccfb81a107a9dd1ef081"
	strings:
		$a = "mahmoodab99@gm"
	condition:
		all of ($a)
}


rule WoscSpy_a
{
  meta:
    description = "Rule for the detection of a Spyware by 'Wosc Development'"
    sample = "0e3324dd8ea86a6326bb23a79d3b3a02d1ee7068d934e1f2ce2300eaaf6630b1"
  strings:
    $mainactivity = "ActivityActivacionInicial"
  condition:
	androguard.certificate.sha1("0E6DC2A27BA2F155C51D8D5AF36D140F92AE203C") or
	androguard.certificate.sha1("89F539729637A67C6BB5A218B00CB3EBDDE2D18D") or
	androguard.certificate.sha1("435CEF8BDA4A8EEF787B0EA6B90E60ECE804459B") or
	androguard.url(/wosc\.net/) or
	androguard.url(/espiar-celular\.com/) or
	androguard.package_name("com.espiarCelular") or
	androguard.package_name("com.espCel2") or
	androguard.package_name(/\*.wosc.\*/) or
	$mainactivity
  }


rule banker_ip_control_a: banker candc
{
	meta:
		description = "g = string = properties.getProperty('xmpp', '126.5.122.217');"
	strings:
		$ip = "xmpp=126.5.122.217"
		$brc = "net.piao.mobile.MYBROADCAST"
	condition:
		any of them
}
rule banker_cromosome_a
{
	meta: 
		description = "get strings for cromosome.py use a lot of samples"
	strings:
		$string_a = "http://impl.service.server.phonemanager.org"
		$string_b = "http://%1$s/PhoneManager/services/BankWebService?wsdl"
		$string_c = "(init system configuration args.........."
		$string_d = "parse phoneLog json data error!!!!"
	condition:
		($string_a or $string_b) and any of ($string_c, $string_d)
}
rule banker_cert_a: cert
{
	meta:
		description = "This rule detects by banker certificates. Valid certificate A828FB8872A1127B131232F00B46B6DA05DEAF51"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.certificate.sha1("1D20151ACC7D0F32F4054C4BE9559129512C2A52") or
		androguard.certificate.sha1("FF8F43BB67FADCD49BA75DDC29523EF10301B0C5") or
		androguard.certificate.sha1("B5A8D5C64BD67D0BDD7937A09F70325A99EB9EFA") or
		androguard.certificate.sha1("3196E8E65F55B44B5C9414C2BC3B8CBCBEEF9467") or
		androguard.certificate.sha1("C0A4F86CF0012139BBB9728001C3B011B468F268") or
		androguard.certificate.sha1("7D7B5AB62AE9249C2F1BE8D2815B99FFC0D53749") or
		androguard.certificate.sha1("8527B91FE37B33FEC02E6F3E176C63A425A799C6") or
		androguard.certificate.sha1("0F1CA787A6F5760CF7D74CEB7475AD1BC83ADECC") or
		androguard.certificate.sha1("DB03AEC0586929BF8B4EFAF54BAD0AC5509FD8BE") or
		androguard.certificate.sha1("6EAC736931F21F7ED5525A69B52BF7D3274542A1") or		
   		androguard.certificate.sha1("C21676E8EFBA88235C8FCE4D023797173401FE3C") or
		androguard.certificate.sha1("01AAD3AA7949A89B36F1F44AFA266F3113C6E615") or
		androguard.certificate.sha1("7F565F25BA98DEF913538F411914EF0EE74F10EE")
}


rule Xavier_a: basic
{
	meta:
		description = "This rule detects the Xavier malicious ad library"
		sample = "6013393b128a4c6349b48f1d64c55aa14477e28cc747b57a818e3152915b14cc/analysis"
		reference = "http://thehackernews.com/2017/06/android-google-play-app-malware.html"
	condition:
		androguard.activity("xavier.lib.XavierActivity") and
		androguard.service("xavier.lib.message.XavierMessageService")
}


rule XavierCampaign_a
{
	meta:
		description = "This rule detects samples from the Xavier campaign"
		sample = "8a72124709dd0cd555f01effcbb42078"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/analyzing-xavier-information-stealing-ad-library-android/"
	condition:
		androguard.service(/xavier.lib.message/) and 
		androguard.receiver(/xavier.lib.Xavier/)
}


rule ms_a: XBOT
{
	meta:
		description = "XBOT"
		source = "http://researchcenter.paloaltonetworks.com/2016/02/new-android-trojan-xbot-phishes-credit-cards-and-bank-accounts-encrypts-devices-for-ransom/"
	strings:
		$a0 = /melon25.ru+/
		$a1 = /81.94.205.226:8021+/
		$a2 = /104.219.250.16:8022+/
		$a3 = /52.24.219.3\/action.php+/
		$a4 = /192.227.137.154\/request.php+/
		$a5 = /23.227.163.110\/locker.php+/
		$a6 = /market155.ru\/Install.apk+/
		$a7 = /illuminatework.ru\/Install.apk+/
		$a8 = /yetiathome15.ru\/Install.apk+/
		$a9 = /leeroywork3.co\/install.apk+/
		$a10 = /morning3.ru\/install.apk+/
		$a11 = /\+79262+/
	condition:
		file.sha1("dfda8e52df5ba1852d518220363f81a06f51910397627df6cdde98d15948de65") or
		file.sha1("e905d9d4bc59104cfd3fc50c167e0d8b20e4bd40628ad01b701a515dd4311449") or
		file.sha1("f2cfbc2f836f3065d5706b9f49f55bbd9c1dae2073a606c8ee01e4bbd223f29f") or
		file.sha1("029758783d2f9d8fd368392a6b7fdf5aa76931f85d6458125b6e8e1cadcdc9b4") or
		file.sha1("1264c25d67d41f52102573d3c528bcddda42129df5052881f7e98b4a90f61f23") or
		file.sha1("20bf4c9d0a84ac0f711ccf34110f526f2b216ae74c2a96de3d90e771e9de2ad4") or
		file.sha1("33230c13dcc066e05daded0641f0af21d624119a5bb8c131ca6d2e21cd8edc1a") or
		file.sha1("4b5ef7c8150e764cc0782eab7ca7349c02c78fceb1036ce3064d35037913f5b6") or
		file.sha1("7e939552f5b97a1f58c2202e1ab368f355d35137057ae04e7639fc9c4771af7e") or
		file.sha1("93172b122577979ca41c3be75786fdeefa4b80a6c3df7d821dfecefca1aa6b05") or
		file.sha1("a22b55aaf5d35e9bbc48914b92a76de1c707aaa2a5f93f50a2885b0ca4f15f01") or
		file.sha1("d082ec8619e176467ce8b8a62c2d2866d611d426dd413634f6f5f5926c451850") or
		file.sha1("a94cac6df6866df41abde7d4ecf155e684207eedafc06243a21a598a4b658729") or
		file.sha1("58af00ef7a70d1e4da8e73edcb974f6ab90a62fbdc747f6ec4b021c03665366a") or
		file.sha1("7e47aaa8a1dda7a413aa38a622ac7d70cc2add1137fdaa7ccbf0ae3d9b38b335") or
		file.sha1("d1e5b88d48ae5e6bf1a79dfefa32432b7f14342c2d78b3e5406b93ffef37da03") or
		file.sha1("c2354b1d1401e31607c770c6e5b4b26dd0374c19cc54fc5db071e5a5af624ecc") or
		file.sha1("12f75b8f58e1a0d88a222f79b2ad3b7f04fd833acb096bb30f28294635b53637") or		
		file.sha1("1b84e7154efd88ece8d6d79afe5dd7f4cda737b07222405067295091e4693d1b") or
		file.sha1("616b13d0a668fd904a60f7e6e18b19476614991c27ef5ed7b86066b28952befc") or	
		file.sha1("2e2173420c0ec220b831f1c705173c193536277112a9716b6f1ead6f2cad3c9e") or
		file.sha1("595fa0c6b7aa64c455682e2f19d174fe4e72899650e63ab75f63d04d1c538c00") or
		$a0 or $a1 or $a2 or $a3 or $a4 or $a5 or $a6 or $a7 or $a8 or $a9 or $a10 or $a11
}


rule xbot007_a
{
	meta:
		source = "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"
	strings:
		$a = "xbot007"
	condition:
		any of them
}


rule Xbot_certs_a
{
	meta:
		description = "http://researchcenter.paloaltonetworks.com/2016/02/new-android-trojan-xbot-phishes-credit-cards-and-bank-accounts-encrypts-devices-for-ransom/"
		sample = "595fa0c6b7aa64c455682e2f19d174fe4e72899650e63ab75f63d04d1c538c00"
	condition:
		androguard.certificate.sha1("CC9966F3860984948D55176357F853D5DBB5C15F") or
		androguard.certificate.sha1("25D6A5507F3262ADF65639C0BA7B0997AE35C36D") or
		androguard.certificate.sha1("27F8BD306E03B3BAAB8A57A7EC6F1CAE71B321EE")
}
rule Xbot_domains_a
{
	meta:
        description = "Xbot domains/IPs"
	strings:
		$1 = "melon25.ru" wide ascii
		$2 = "market155.ru" wide ascii
		$3 = "illuminatework.ru" wide ascii
		$4 = "yetiathome15.ru" wide ascii
		$5 = "leeroywork3.co" wide ascii
		$6 = "morning3.ru" wide ascii	
		$7 = "52.24.219.3/action.php" wide ascii			
		$8 = "192.227.137.154/request.php" wide ascii
		$9 = "23.227.163.110/locker.php" wide ascii
		$10 = "81.94.205.226:8021" wide ascii
		$11 = "104.219.250.16:8022" wide ascii			
   	condition:
		1 of them or
		cuckoo.network.dns_lookup(/melon25.ru/) or
		cuckoo.network.dns_lookup(/market155.ru/) or
		cuckoo.network.dns_lookup(/illuminatework.ru/) or
		cuckoo.network.dns_lookup(/yetiathome15.ru/) or
		cuckoo.network.dns_lookup(/leeroywork3.co/) or
		cuckoo.network.dns_lookup(/morning3.ru/)
}
rule Xbot_pass_a
{
	meta:
        description = "Xbot password"
	strings:
		$1 = "resetPassword" wide ascii
		$2 = "1811blabla" wide ascii
   	condition:
		all of them
}
rule Xbot_evidences_a
{
	meta:
        description = "Xbot evidences"
	strings:
		$1 = "Lcom/xbot/core/activities/BrowserActivity" wide ascii
		$2 = "/xBot.log.txt" wide ascii
		$3 = "com.xbot.core" wide ascii		
   	condition:
		1 of them
}


/**/
private rule Xynyin_certs
{
	meta:
		description = "Fake developers certs and email: smo_XXXX_t@gmail.com"
	condition:
		androguard.certificate.issuer(/smo_[0-9]{3,4}_t\@gmail\.com/) or	
		androguard.certificate.sha1("A1B5344F6E8EB1305EE7B742CDDBEFAF2041CB89") or
		androguard.certificate.sha1("CB48901569936E9322103EA806F386ED2401583F") or
		androguard.certificate.sha1("171F1EFF24F580EE28AF7C30C1190AB717A96DCE") or
		androguard.certificate.sha1("DCD5BA60AC48996A11D126354978E9A909D90229")		
}
private rule Xynyin_cyphered
{
	meta:
		description = "Cyphered files by Xynyin"
	strings:	
		$1 = "assets/version.txt" wide ascii
		$2 = "assets/ecode"	 wide ascii
		$3 = "assets/ecode_64" wide ascii	
	condition:
		all of them
}
rule Xynyin_strings_a
{
	meta:
		description = "Xynyin particular strings"
	strings:	
		$2 = "zzzsurpriseprjsnotificationcontent" wide ascii
		$3 = "zzzltid" wide ascii		
	condition:
		1 of them and Xynyin_cyphered and Xynyin_certs
}
rule shuabang_evidences_a
{
	meta:
		description = "Xynyin/shuabang based"
	strings:			
		$1 = "ShuaBangBase"
		$2 = "ShuaPublicConfig"
		$3 = "Start BindLMT!"
	condition:
		all of them and Xynyin_certs
}


rule YaYaBanker2_a: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "05 Jan 2018"
		url = "https://koodous.com/apks?search=e96b38e2f76e38e5a02f41eec626330799e6b20a3ddfdaa2da62c0672fc8cbf5%20OR%20%200c5a24d64e0b6a7ad2d5b7fe928b939b6635f1129dc2239057bd381a94ce9aed%20OR%20%204680ec774eabfa22fff77eed8ee47da5ffc4b3563b29c313b51453cf161e7cc2%20OR%20%209f9412fe618c239227184189d71eab3e998db22b625a3324832734bb05b4aa0b%20OR%20%207c28b64d3e6a529cf3b3cfb308c4cba9e624271c2215575cbd0b66551fc0d9fe%20OR%20%200f6530b8120399437b256f7f5004dffc5763f2397382318ad313e16943641224%20OR%20%200852925981807512a1367fb7423956b2b2dbe617a42952de4e1af08a611f21d7%20OR%20%2012fd9f2a9150414618770353c0661d422091bdcddaae814f26401fa826da9423%20OR%20%20e44e54ddf46457eafc368c17e353e8aeb119f20f8c38060daed1d954670e1c87%20OR%20%2072c733e3fdf7ee9f74e4473f7e872a2aa6b425d249ad186c98615f9b3766f197"
	condition:
		androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/Context\;\-\>unregisterReceiver\(Landroid\/content\/BroadcastReceiver\;\)V/) and 
		androguard.functionality.dynamic_broadcast.code(/invoke\-virtual\ v0\,\ v1\,\ v2\,\ Landroid\/content\/Context\;\-\>registerReceiver\(Landroid\/content\/BroadcastReceiver\;\ Landroid\/content\/IntentFilter\;\)Landroid\/content\/Intent\;/) and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_EXTERNAL_STORAGE") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
		((androguard.url("/add.php") or 
		cuckoo.network.http_request(/\/add\.php/)) or 
		(androguard.url("/chins.php") or 
		cuckoo.network.http_request(/\/chins\.php/)) or 
		(androguard.url("/live.php") or 
		cuckoo.network.http_request(/\/live\.php/)))
}


rule YaYaBankerHQFuncionalitySSL_a: rule0 {
	meta:
		author = "YaYaGen --/ Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "03 Jan 2018"
		url = "https://koodous.com/apks?search=204f2e5e18691156036cbcfc69fa759272a2180fba77a74415ccb2c7469a670b%20OR%2086aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5"
	condition:
		androguard.functionality.ssl.code(/const\-string\ v1\,\ \"\(\(\(\?\:\(\?i\:http\|https\|rtsp\)\:\/\/\(\?\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,64\}\(\?\:\\\\\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,25\}\)\?\\\\\@\)\?\)\?\(\?\:\"/) and 
		androguard.functionality.ssl.code(/const\-string\ v1\,\ \"\(\(\?\:\\\\b\|\$\|\^\)\(\?\:\(\?\:\(\?i\:http\|https\|rtsp\)\:\/\/\(\?\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,64\}\(\?\:\\\\\:\(\?\:\[a\-zA\-Z0\-9\\\\\$\\\\\-\\\\_\\\\\.\\\\\+\\\\\!\\\\\*\\\\\'\\\\\(\\\\\)\\\\\,\\\\\;\\\\\?\\\\\&\\\\\=\]\|\(\?\:\\\\\%\[a\-fA\-F0\-9\]\{2\}\)\)\{1\,25\}\)\?\\\\\@\)\?\)\(\?\:\"/) and 
		androguard.functionality.ssl.code(/const\-string\ v1\,\ \'https\:\/\/\'/)
}


rule YaYaCatelites_a: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "04 Jan 2018"
		url = "https://koodous.com/apks?search=0e741a21228f4f7ffdbb891524f3a246b60bee287965a74fe15009127f6de280%20OR%20%2014c7e547cb8dc8f5d629725fdbdd2e8c33693dd407b2f36cd03c613e59af2cc7%20OR%20%20efe6d86d7482fbcb5b1e7e12e22c2b086e4ec988939ebdffc9d363413e5a3326%20OR%20%20bf6a4b8c24cd4cf233137dcee735bc33849d34e659ec2fa5e0fa9b425fee9b4e%20OR%20%20e174dd174c5e21daa86064562aaf274d3f6fe84f4a3970beed48c02c3b605d58%20OR%20%20b81e0b6fe123b8d4cf7d99c20de1c694360d146bf80d9490b1b0325a00bf7f5a%20OR%20%200c50311ee3e30fe5be1b863db1b60b32bc9afa8d4264b852a836220751c7e3b2%20OR%20%20d8452b39b1962239e9dbe12e8a9d8d0ee098b9c8de8a8d55b5a95b67b552102f%20OR%20%2053dc796e2e77689b115701a92ad2bdaeb0c7a4e87bc9e9a0bbeda057b77e22ee"
	condition:
		androguard.app_name("System Application") and 
		androguard.filter("android.app.action.ACTION_DEVICE_ADMIN_DISABLE_REQUESTED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.PACKAGE_ADDED") and 
		androguard.filter("android.intent.action.PACKAGE_REMOVED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.intent.action.SEND") and 
		androguard.filter("android.intent.action.SENDTO") and 
		androguard.filter("android.intent.action.USER_PRESENT") and 
		androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON")
}


rule YaYaExobot_a: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "05 Jan 2018"
		url = "https://koodous.com/apks?search=1cd3095b176520e4bf7d3fa86ec91e852ee93b2172c8bd3113f91e2569a7c481%20OR%20%20ca2cc26e81196a2031a5cdeda91a6624ba9d34e03e5b1448dd682b0215134d15%20OR%20%2077e26712490e8ec681881b584c5e381af0dcece21f0dcfa483661f125a399a2d%20OR%20%208e9bdb1f5a37471f3f50cc9d482ea63c377e84b73d9bae6d4f37ffe403b9924e%20OR%20%20ca859564cfbfca3c99ab38c9cb30ad33ec9049fe67734bae9d9b69cd68845188%20OR%20%2059ada6b530bd2c7c15d8c552c7ebf3afcc14976bfa789a6e2c2fca3e354baab0%20OR%20%20c1ef19c9abc479070d7841846ff6b4c973b34b2035428b50999ebe63eb0547db%20OR%20%20da68cc23a89c2b794827e9f846ed5d1e371a1c14229696bc46a4d9ec380425d4%20OR%20%20498304e3f60abe29bb06661b21e579d5a25f104eb96ebf0d5d573ce9f8308b89%20OR%20%20690310a635b5c82c28a76332b83a7b34b8604e822ed8f8e4eb1f0be85c177c62%20OR%20%20ae4ed005f891101b297689530e9d07068e0a0779c7a03abe36f30b991b065ff9%20OR%20%20c28b6346d59a828ce319e94d08c35b530ae39fd5801d17e6f84a02a592621e2d%20OR%20%201cd3095b176520e4bf7d3fa86ec91e852ee93b2172c8bd3113f91e2569a7c481%20OR%20%20b8b424866ba77728034e231f295399f523154accf587424c9d42cbb1c8edba9e%20OR%20%2092c560d55ac0943022be38404fee8fd70da53cca33d7e340ea98712af389f780%20OR%20%20856d1f7cf037e031dda4accc3454d84115bc91be488b74817580e541be6abbad%20OR%20%202d1d9cabf564bc9c3a37c21cd98c7c045453dc583fab4479fe12d8e4e70f339a%20OR%20%20f6851790dc811b3a9acc425730ffeaab49c5cde4cb0a39cfcc659c4d29c908ad%20OR%20%2010931ae2c165d4786fdd9585c419a6b1d2dd07d96242d26d23daab14d684f4e0"
	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.RECEIVE_SMS") and 
		androguard.permission("android.permission.SEND_SMS") and 
		androguard.permission("android.permission.USES_POLICY_FORCE_LOCK")
}


rule YaYaGhostPush_a {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "29 Dec 2017"
		url = "https://koodous.com/apks?search=0f9e0b86fd3685ee0960ad6dfdc9e2e03c81ce203888546d3cc7740c0a07e5aa%20OR%20%205fbcab01cf7b231d3cc0b26b86e58c95a82cebaa34e451b7b4d3f5e78dad3ea5%20OR%20%2003eda7f7ecaa6425d264d82fb22e7b7218dfdd17bf9d5bbdd70045fecb3eb0e5"
	condition:
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.CAMERA") and 
		androguard.permission("android.permission.GET_ACCOUNTS") and 
		androguard.permission("android.permission.KILL_BACKGROUND_PROCESSES") and 
		androguard.permission("android.permission.READ_SETTINGS") and 
		androguard.permission("android.permission.RECEIVE_USER_PRESENT") and 
		androguard.permission("android.permission.WRITE_SETTINGS") and 
		androguard.service("com.android.wp.net.log.UpService") and 
		androguard.service("com.android.wp.net.log.service.ActivateService")
}


rule YaYaGMBanker_a {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "29 Dec 2017"
		url = "https://koodous.com/apks?search=Bd8502a1f9934d0c1f7bb44f0b4fd7f7765798225bd2192f3fff76f5cb55259a%20OR%209425fca578661392f3b12e1f1d83b8307bfb94340ae797c2f121d365852a775e%20OR%20960422d069c5bcf14b2acbefac99b4c57b857e2a2da199c69e4526e0defc14d7%20OR%20306ca47fdf2db0010332d58f2f099d702046aa1739157163ee75177e1b9d5455"
	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.filter("com.slempo.service.activities.HTMLStart")
}


rule YaYaLokibot_a: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "04 Jan 2018"
		url = "https://koodous.com/apks?search=be02cf271d343ae1665588270f59a8df3700775f98edc42b3e3aecddf49f649d%20OR%20%201979d60ba17434d7b4b5403c7fd005d303831b1a584ea2bed89cfec0b45bd5c2%20OR%20%20a10f40c71721668c5050a5bf86b41a1d834a594e6e5dd82c39e1d70f12aadf8b%20OR%20%205c1857830053e64082d065998ff741b607186dc3414aa7e8d747614faae3f650%20OR%20%20cd44705b685dce0a6033760dec477921826cd05920884c3d8eb4762eaab900d1%20OR%20%20bae9151dea172acceb9dfc27298eec77dc3084d510b09f5cda3370422d02e851%20OR%20%20418bdfa331cba37b1185645c71ee2cf31eb01cfcc949569f1addbff79f73be66%20OR%20%20a9899519a45f4c5dc5029d39317d0e583cd04eb7d7fa88723b46e14227809c26%20OR%20%206fb961a96c84a5f61d17666544a259902846facb8d3e25736d93a12ee5c3087c%20OR%20%20c9f56caaa69c798c8d8d6a3beb0c23ec5c80cab2e99ef35f2a77c3b7007922df%20OR%20%2039b7ff62ec97ceb01e9a50fa15ce0ace685847039ad5ee66bd9736efc7d4a932%20OR%20%2078feb8240f4f77e6ce62441a6d213ee9778d191d8c2e78575c9e806a50f2ae45%20OR%20%20a09d9d09090ea23cbfe202a159aba717c71bf2f0f1d6eed36da4de1d42f91c74%20OR%20%20f4d0773c077787371dd3bebe93b8a630610a24d8affc0b14887ce69cc9ff24e4%20OR%20%2018c19c76a2d5d3d49f954609bcad377a23583acb6e4b7f196be1d7fdc93792f8%20OR%20%20cda01f288916686174951a6fbd5fbbc42fba8d6500050c5292bafe3a1bcb2e8d%20OR%20%207dbcecaf0e187a24b367fe05baedeb455a5b827eff6abfc626b44511d8c0029e"
	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.ACTION_BATTERY_OKAY") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.NEW_OUTGOING_CALL") and 
		androguard.filter("android.intent.action.PACKAGE_ADDED") and 
		androguard.filter("android.intent.action.PACKAGE_REMOVED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON") and 
		androguard.permission("android.permission.QUICKBOOT_POWERON")
}


rule YaYaMarcher_a: ruleDef {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "05 Jan 2018"
		url = "https://koodous.com/apks?search=b087728f732ebb11c4a0f06e02c6f8748d621b776522e8c1ed3fb59a3af69729%20OR%20%205bb9b9173496d8b70093ef202ed0ddddd48ad323e594345a563a427c1b2ebc22%20OR%20%20c8f753904c14ecee5d693ce454353b70e010bdaf89b2d80c824de22bd11147d5%20OR%20%20c172567ccb51582804e589afbfe5d9ef4bc833b99b887e70916b45e3a113afb8%20OR%20%20fcd18a2b174a9ef22cd74bb3b727a11b4c072fcef316aefbb989267d21d8bf7d%20OR%20%20a1258e57c013385401d29b75cf4dc1559691d1b2a9afdab804f07718d1ba9116%20OR%20%20a1258e57c013385401d29b75cf4dc1559691d1b2a9afdab804f07718d1ba9116%20OR%20%20ed2b26c9cf4bc458c2fa89476742e9b0d598b0c300ab45e5211f29dfd9ddd67b%20OR%20%20be6c8a4afbd4b31841b2d925079963f3bd5422a5ee5f248c5ed5013093c21cf9%20OR%20%20ec4d182b0743dbdedb989d4f4cb2d607034ee1364c30103b2415ea8b90df8775%20OR%20%205a9e3d2c2ef29b76c628e70a91575dc4be3999b60f34cab35ee70867faaff4a0%20OR%20%205df132235eccd1e75474deca5b95e59e430e23a22f68b6b27c2c3a4aeb748857%20OR%20%2025e07c50707c77c8656088a9a7ff3fdd9552b5b8022d8c154f73dca1e631db4f%20OR%20%20f7743a01fc80484242d59868938ec64990c19bea983fb58b653822c9ee3306a1%20OR%20%206f8b7aa6293238d23b1c5236d1c10cecc54ec8407007887e99ea76f9fce51075%20OR%20%207f08cc20aa6e1256f6a8db3966ac71ad209db6dff14a6dde0fd7b2407c2c23e7%20OR%20%20b4e5affbc3ea94eb771614550bc83fde85f90caddcca90d25704c9a556f523da"
	condition:
		androguard.certificate.sha1("5927F6909E6B56B96021B2CDC3F0A0989BBE93B6") or
		(androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v1\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v10\,\ Landroid\/view\/KeyEvent\;\-\>getDeviceId\(\)I/) and 
		androguard.functionality.installed_app.code(/invoke\-virtual\ v0\,\ v1\,\ Landroid\/content\/pm\/PackageManager\;\-\>getInstalledApplications\(I\)Ljava\/util\/List\;/) and 
		androguard.functionality.phone_number.code(/invoke\-virtual\ v1\,\ Landroid\/telephony\/TelephonyManager\;\-\>getLine1Number\(\)Ljava\/lang\/String\;/) and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.GET_TASKS") and 
		androguard.permission("android.permission.SEND_SMS") and 
		androguard.permission("android.permission.VIBRATE")) or 
		androguard.url("loupeacara.net") or
		androguard.url("sarahtame.at") or
		androguard.url("loupeahak.com") or
		androguard.url("chudresex.at") or
		androguard.url("chudresex.cc") or
		androguard.url("memosigla.su") or
		androguard.url("rockybalboa.at") or
		androguard.url("storegoogle.at") or
		androguard.url("trackgoogle.at") or
		androguard.url("track-google.at") or
		androguard.url("coupon-online.fr") or
		androguard.url("inovea-engineering.com") or
		androguard.url("lingerieathome.eu") or
		androguard.url("playgoogle.at") or
		androguard.url("i-app5.online") or
		androguard.url("i-app4.online") or
		androguard.url("i-app1.online") or
		androguard.url("176.119.28.74") or
		androguard.url("soulreaver.at") or
		androguard.url("olimpogods.at") or
		androguard.url("divingforpearls.at") or
		androguard.url("fhfhhhrjtfg3637fgjd.at") or
		androguard.url("dfjdgxm3753u744h.at") or
		androguard.url("dndzh457thdhjk.at") or
		androguard.url("playsstore.mobi") or
		androguard.url("secure-ingdirect.top") or
		androguard.url("playsstore.net") or
		androguard.url("compoz.at") or
		androguard.url("cpsxz1.at") or
		androguard.url("securitybitches3.at") or
		androguard.url("wqetwertwertwerxcvbxcv.at") or
		androguard.url("securitybitches1.at") or
		androguard.url("ldfghvcxsadfgr.at") or
		androguard.url("weituweritoiwetzer.at") or
		androguard.url("wellscoastink.biz") or
		androguard.url("deereebee.info") or
		androguard.url("ssnoways.info") or
		androguard.url("elitbizopa.info") or
		androguard.url("filllfoll.biz") or
		androguard.url("bizlikebiz.biz") or
		androguard.url("barberink.biz") or
		androguard.url("nowayright.biz") or
		androguard.url("messviiqqq.info") or
		androguard.url("qqqright.info") or
		androguard.url("sudopsuedo1.su") or
		androguard.url("sudopsuedo2.su") or
		androguard.url("sudopsuedo3.su") or
		androguard.url("androidpt01.asia") or
		androguard.url("androidpt02.asia")
}


rule YaYaNGEMobi_a: rule1 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "03 Jan 2018"
		url = "https://koodous.com/apks?search=12b8da40ec9e53a83a7c4b1d490db397730123efa5e8ed39ee596d3bae42f80d%20OR%20%208b5b898c7ad2fc6b516800f411b7181877a89124a94ba8a9fa0e974972c67553%20OR%20%20d65696c077b480bb0afab2390f1efd37d701ca2f6cbaa91977d4ac76957438c7%20OR%20%203a5bbe5454124ba5fbaa0dc7786fd2361dd903f84ccf65be65b0b0b77d432e6e%20OR%20%20b05013bbabf0a24a2c8b9c7b3f3ad79b065c6daaaec51c2e61790b05932dbb58%20OR%20%20396324dc3f34785aca1ece255a6f142f52e831b22bf96906c2a10b61b1da4713%20OR%20%2098bdad683b0ae189ed0fa56fb1e147c93e96e085dff90565ee246a4f6c4e2850%20OR%20%20f46c21a2976af7ba23e0af54943eacdaad2fd0b3108fde6d1502879fe9c83d07%20OR%20%20b3c3d131200369d1c28285010b99d591f9a9c0629b0ba9fedd1b4ffe0170cf4c%20OR%20%200a63ca301d97930eb8352c0772fb39015e4b89cd82e72391213ee82414e60cf8"
	condition:
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.USER_PRESENT") and 
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and 
		androguard.permission("android.permission.ACCESS_MTK_MMHW") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.CAMERA") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.WAKE_LOCK")
}


rule YaYaRedAlert_a: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "04 Jan 2018"
		url = "https://koodous.com/apks?search=a7c9cfa4ad14b0b9f907db0a1bef626327e1348515a4ae61a20387d6ec8fea78%20OR%20%20bb0c8992c9eb052934c7f341a6b7992f8bb01c078865c4e562fd9b84637c1e1b%20OR%20%2079424db82573e1d7e60f94489c5ca1992f8d65422dbb8805d65f418d20bbd03a%20OR%20%204d74b31907745ba0715d356e7854389830e519f5051878485c4be8779bb55736%20OR%20%202dc19f81352e84a45bd7f916afa3353d7f710338494d44802f271e1f3d972aed%20OR%20%20307f1b6eae57b6475b4436568774f0b23aa370a1a48f3b991af9c9b336733630%20OR%20%20359341b5b4306ef36343b2ed5625bbbb8c051f2957d268b57be9c84424affd29%20OR%20%209eaa3bb33c36626cd13fc94f9de88b0f390ac5219cc04a08ee5961d59bf4946b%20OR%20%20dc11d9eb2b09c2bf74136b313e752075afb05c2f82d1f5fdd2379e46089eb776%20OR%20%2058391ca1e3001311efe9fba1c05c15a2b1a7e5026e0f7b642a929a8fed25b187%20OR%20%2036cbe3344f027c2960f7ac0d661ddbefff631af2da90b5122a65c407d0182b69%20OR%20%20a5db9e4deadb2f7e075ba8a3beb6d927502b76237afaf0e2c28d00bb01570fae%20OR%20%200d0490d2844726314b7569827013d0555af242dd32b7e36ff5e28da3982a4f88%20OR%20%203e47f075b9d0b2eb840b8bbd49017ffb743f9973c274ec04b4db209af73300d6%20OR%20%2005ea7239e4df91e7ffd57fba8cc81751836d03fa7c2c4aa1913739f023b046f0%20OR%20%209446a9a13848906ca3040e399fd84bfebf21c40825f7d52a63c7ccccec4659b7%20OR%20%203a5ddb598e20ca7dfa79a9682751322a869695c500bdfb0c91c8e2ffb02cd6da%20OR%20%20b83bd8c755cb7546ef28bac157e51f04257686a045bbf9d64bec7eeb9116fd8a"
	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.intent.action.SEND") and 
		androguard.filter("android.intent.action.SENDTO") and 
		androguard.filter("android.provider.Telephony.SMS_DELIVER") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.functionality.crypto.code(/invoke\-virtual\ v0\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\)\[B/) and 
		androguard.functionality.iccid.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getSimSerialNumber\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imsi.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getSubscriberId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.installed_app.code(/invoke\-virtual\ v0\,\ v2\,\ Landroid\/content\/pm\/PackageManager\;\-\>getInstalledApplications\(I\)Ljava\/util\/List\;/) and 
		androguard.functionality.phone_number.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getLine1Number\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.run_binary.code(/invoke\-static\ Ljava\/lang\/Runtime\;\-\>getRuntime\(\)Ljava\/lang\/Runtime\;/) and 
		androguard.functionality.run_binary.code(/invoke\-virtual\ v0\,\ v1\,\ Ljava\/lang\/Runtime\;\-\>exec\(Ljava\/lang\/String\;\)Ljava\/lang\/Process\;/) and 
		androguard.functionality.sms.code(/invoke\-virtual\/range\ v0\ \.\.\.\ v5\,\ Landroid\/telephony\/SmsManager\;\-\>sendTextMessage\(Ljava\/lang\/String\;\ Ljava\/lang\/String\;\ Ljava\/lang\/String\;\ Landroid\/app\/PendingIntent\;\ Landroid\/app\/PendingIntent\;\)V/) and 
		androguard.functionality.sms.method(/onHandleIntent/) and 
		androguard.functionality.socket.code(/invoke\-virtual\ v0\,\ Ljava\/net\/URL\;\-\>openConnection\(\)Ljava\/net\/URLConnection\;/)
}


rule YaYaRuleEXOBOT_a: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "19 Jan 2018"
		description = "https://clientsidedetection.com/exobot_android_malware_spreading_via_google_play_store.html"
	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLE_REQUESTED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.PACKAGE_ADDED") and 
		androguard.filter("android.intent.action.USER_PRESENT") and 
		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.run_binary.code(/invoke\-static\ Ljava\/lang\/Runtime\;\-\>getRuntime\(\)Ljava\/lang\/Runtime\;/) and 
		androguard.functionality.run_binary.code(/invoke\-virtual\ v1\,\ v2\,\ Ljava\/lang\/Runtime\;\-\>exec\(Ljava\/lang\/String\;\)Ljava\/lang\/Process\;/) and 
		androguard.functionality.run_binary.method(/a/) and 
		androguard.functionality.ssl.method(/\<clinit\>/) and 
		androguard.number_of_filters == 7 and 
		androguard.number_of_receivers == 2 and 
		androguard.number_of_services == 2 and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE")
}


rule YaYaRuleEXOBOTDropped_a: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "19 Jan 2018"
		description = "Dropped apps: https://clientsidedetection.com/exobot_android_malware_spreading_via_google_play_store.html"
	condition:
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.functionality.crypto.code(/invoke\-virtual\ v0\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\)\[B/) and 
		androguard.functionality.crypto.code(/invoke\-virtual\ v6\,\ Ljava\/security\/MessageDigest\;\-\>digest\(\)\[B/) and 
		androguard.functionality.crypto.method(/a/) and 
		androguard.functionality.crypto.method(/b/) and 
		androguard.functionality.dynamic_broadcast.method(/onBind/) and 
		androguard.functionality.imei.class(/Landroid\/support\/v7\/a\/j\;/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v0\,\ Landroid\/telephony\/TelephonyManager\;\-\>getDeviceId\(\)Ljava\/lang\/String\;/) and 
		androguard.functionality.imei.code(/invoke\-virtual\ v10\,\ Landroid\/view\/KeyEvent\;\-\>getDeviceId\(\)I/) and 
		androguard.functionality.imei.method(/a/) and 
		androguard.functionality.imei.method(/b/) and
		androguard.permission("android.permission.ACCESS_FINE_LOCATION") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.READ_CONTACTS")
}


rule YaYAXinyinhe_a {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "29 Dec 2017"
		url = "https://koodous.com/apks?search=12b8da40ec9e53a83a7c4b1d490db397730123efa5e8ed39ee596d3bae42f80d%20OR%208b5b898c7ad2fc6b516800f411b7181877a89124a94ba8a9fa0e974972c67553%20OR%20d65696c077b480bb0afab2390f1efd37d701ca2f6cbaa91977d4ac76957438c7%20OR%203a5bbe5454124ba5fbaa0dc7786fd2361dd903f84ccf65be65b0b0b77d432e6e%20OR%20b05013bbabf0a24a2c8b9c7b3f3ad79b065c6daaaec51c2e61790b05932dbb58%20OR%20396324dc3f34785aca1ece255a6f142f52e831b22bf96906c2a10b61b1da4713%20OR%2098bdad683b0ae189ed0fa56fb1e147c93e96e085dff90565ee246a4f6c4e2850%20OR%20f46c21a2976af7ba23e0af54943eacdaad2fd0b3108fde6d1502879fe9c83d07%20OR%20b3c3d131200369d1c28285010b99d591f9a9c0629b0ba9fedd1b4ffe0170cf4c%20OR%200a63ca301d97930eb8352c0772fb39015e4b89cd82e72391213ee82414e60cf8"
	condition:
		androguard.filter("android.intent.action.BOOT_COMPLETED") and
		androguard.filter("android.intent.action.USER_PRESENT") and
		androguard.filter("android.net.conn.CONNECTIVITY_CHANGE") and
		androguard.permission("android.permission.ACCESS_MTK_MMHW") and
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and
		androguard.permission("android.permission.CAMERA") and
		androguard.permission("android.permission.INTERNET") and
		androguard.permission("android.permission.READ_PHONE_STATE") and
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and
		androguard.permission("android.permission.WAKE_LOCK")
}


private rule activity
{
	condition:
		androguard.url(/hotappsxx\.com/) or
		androguard.url(/xvideozlive\.xxx/)
}
rule youpornxxx_a
{
	meta:
		description = "SMSReg variant related with Youpornxxx"
		sample = "686a424988ab4a9340c070c8ac255b632c617eac83680b4babc6f9c3d942ac36"
	strings:
		$a = "newapps/youpornxxx" wide ascii
	condition:
		$a or activity
}


rule zitmo_a
{
	meta:
		description = "Detects Zitmo"
		samples = "d48ce7e9886b293fd5272851407df19f800769ebe4305358e23268ce9e0b8703, e86cdfb035aea4a5cb55efa59a5e68febf2f714525e301b46d99d5e79e02d773"
	strings:
		$a = "REQUEST_SET_ADMIN"
		$b = "RESPONSE_SET_ADMIN"
		$c = "REQUEST_ON"
		$d = "MESSAGE_START_UP"
		$e = "KEY_ADMIN_NUMBER"
		$f = "DEFAULT_ADMIN_NUMBER"
	condition:
		all of them and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/)
}


