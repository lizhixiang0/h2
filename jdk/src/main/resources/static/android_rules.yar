rule koodous_a: official
{
	condition:
		androguard.permission(/com.bsing.hellosing.permission.C2D_MESSAGE/) or
		androguard.permission(/vn.cpgame.pokemonvictoryfire.permission.C2D_MESSAGE/)
}
rule ABTastySDK_a
{
	meta:
		description = "This rule detects ABTasty SDK"
	strings:
		$a = "com.abtasty."
	condition:
		$a or androguard.activity(/com.abtasty.*/)
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
rule Example_a: Malware
{
	meta:
		description = "This rule detects custom URL suspicious C&C"
		sample = ""
		author = "Augusto Morales"
	strings:
		$domain_1 = "adspot.tfgapps.com"
		$domain_2 = "subscriptions-verifier.tfgapps.com"
		$domain_3 = "https://adspot.tfgapps.com/webview/"
		$ip_1 = "52.72.88.181" ascii wide
		$ip_2 = "34.227.145.183" ascii wide
	condition:
		any of ($domain_*) or any of ($ip_*)
}
rule droidb_a
rule myest_a
{
	condition:
		androguard.receiver("com.android.license.CheckLicense") or androguard.service("com.android.license.LicenseService")
}
rule TEST_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e5d8f5095be1d411a9946dd291ec7cca3e81963f574662110486c93d1b0b73b5"
	condition:
		androguard.package_name("com.bigpanda.puzzlegame.dragnmatch") 
}
rule bankbot_discoverer_a
{
	meta:
		description = "This rule detects the bankbot app based on md5 and sha1"
		sample = "b3b4afbf0e2cbcf17b04d1a081517a8f3bcb1d7a4b761ba3e3d0834bd3c96f88"
	condition:
		androguard.certificate.sha1("4126E5EE9FBD407FF49988F0F8DFAA8BB2980F73") and		
		androguard.url(/37.1.207.31\api\?id=7/) or
		androguard.package_name(/untoenynh/) and
		androguard.permission(/SEND_SMS/) and
		androguard.permission(/RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/INTERNET/) and
		androguard.permission(/READ_LOGS/) and
		androguard.permission(/WRITE_SMS/) and
		androguard.permission(/ACCESS_NETWORK_STATE/) and
		androguard.permission(/GET_TASKS/) and
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/RECEIVE_SMS/) and
		androguard.permission(/READ_PHONE_STATE/) and
		androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/READ_CONTACTS/) and
		androguard.permission(/READ_SMS/)
}
rule koodous_b: official
{
	meta:
		description = "mono - network"
	condition:
		androguard.service(/ir.mono/i) or
		androguard.url(/api.\mono\.ir/)
}
rule socks_1000_a: official
{
	meta:
		 description = "This rule detects  Socks4 or Socks5"
	strings:
		$a = "Socks4"
		$b = "Socks5"
	condition:
		$a  or $b
}
rule clonedfdroid_a: pua
{
	meta:
		description = "Find cloned F-Droid Apps"
		sample = "5962770b87a51fe9198ffdece47ca6faafad98e162275bb485833381774a29cd"
		sample = "8ed89b20367d4ff0b375451d314780709cb706c17cc7103e9072ebf8ef2564d4"
	condition:
		(
			androguard.package_name("org.fdroid.fdroie") 
			or
			androguard.package_name("org.fdroid.fdroid")
		)
		and
		(
			androguard.activity(/com\.applisto\.appcloner\.classes.*/)
			or
			androguard.permission(/com.applisto.appcloner.permission.DEFAULT/)
		)
}
rule ILightsService_a: official
{
	meta:
		description = "This rule detects the android.app.ILightsService, see https://wuffs.org/blog/digitime-tech-fota-backdoors"
	condition:
	    androguard.service("android.app.ILightsService")		
}
rule Dresscode_hzytrfd_a: official
{
	meta:
		description = "This rule detects potential dresscode infections based on the hzytrfd package name"
	condition:
		androguard.package_name("hzytrfd") 
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
rule bankbot_discoverer_b
{
	meta:
		description = "This rule detects the bankbot app based on various info"
		sample = "b3b4afbf0e2cbcf17b04d1a081517a8f3bcb1d7a4b761ba3e3d0834bd3c96f88"
		family = "bankbot"
strings:
		$s1 = "overlayMode"
		$s2 = "disable_forward_calls"
		$s3 = "suggest_text_2_url"
		$s4 = "popupWindow"
		$s5 = "rootId"
	condition:
		androguard.package_name("com.tvone.untoenynh") and
		androguard.permission(/android.permission.READ_CONTACTS/) or
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) or
		androguard.permission(/android.permission.RECEIVE_SMS/) or
		androguard.permission(/android.permission.READ_SMS/) or
		androguard.permission(/android.permission.READ_LOGS/) or
		androguard.permission(/android.permission.READ_PHONE_STATE/) or
		androguard.permission(/android.permission.MODIFY_PHONE_STATE/) or
		androguard.permission(/android.permission.QUICKBOOT_POWERON/) or
		androguard.permission(/android.permission.WRITE_SMS/) or
		androguard.permission(/android.permission.GET_TASKS/) or
		androguard.permission(/android.permission.WAKE_LOCK/) or
		androguard.permission(/android.permission.CALL_PHONE/) or
		androguard.permission(/android.permission.MODIFY_AUDIO_SETTINGS/) or
		androguard.permission(/android.permission.INTERNET/) or
		androguard.certificate.sha1("4126E5EE9FBD407FF49988F0F8DFAA8BB2980F73") or
		androguard.url(/37.1.207.31\api\?id=7/) or
		any of ($s*)		
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
rule gretel_com_android_service_a
{
	meta:
		description = "com.android.service"
		sha = "8a8a2f1c13d0d57186bc343af96abe87"
	strings:
		$a_1 = "iwtiger/plugin"
        $a_2 = "com/ryg/dynamicload/DLProxyActivity" 
        $a_3 = "com/ryg/dynamicload/DLBasePluginActivity" 
	condition:
		all of ($a_*) and
		androguard.certificate.sha1("5E7C8FE28537307E28BEB0F82F67DF76F1A119D6")
}
rule Trojan_a: SMSSpy
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
rule DTCLoader_Strngs_a: DTCLOADER
{
	meta:
		description = "Rule used to catch \"DtcLoader\" app strings, which look like malicious"
	strings:
		$ = "entryRunApplication"
		$ = "q~tb\\u007fyt>q``>QsdyfydiDxbuqt"
		$ = "wudCicdu}S\\u007f~duhd"
		$ = "sebbu~dQsdyfydiDxbuqt"
		$ = "\\u786e\\u5b9a"
		$ = "libjiagu"
	condition:
		all of them
}
rule String_ls_Binary_a: DTCLOADER
{
	meta:
		description = "String pointing to ls binary"
	strings:
		$ = "/system/bin/ls"
	condition:
		any of them
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
rule BankingOnline_Strings_BOI_a {
	strings:
		$string_1 = /365online\.com/
		$string_2 = /businessonline\-boi\.com/
	condition:
		1 of ($string_*)
}
rule bankbot_discoverer_c
{
	meta:
		description = "Rule tp detect Bankbot malware"
		sample = "b3b4afbf0e2cbcf17b04d1a081517a8f3bcb1d7a4b761ba3e3d0834bd3c96f88"
	condition:
		androguard.certificate.sha1("4126E5EE9FBD407FF49988F0F8DFAA8BB2980F73") or 
		(androguard.url(/37.1.207.31\api\?id=7/) and 
		androguard.package_name(/untoenynh/) and
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/READ_SMS/)
		)
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
rule GSTPaymentTracker_a
{
	meta:
		description = "This rule detects All apps with GST Payment link"
	strings:
		$a = "https://payment.gst.gov.in/payment/"
		$b = "https://payment.gst.gov.in/payment/trackpayment"
	condition:
		($a or $b) and
		androguard.permission(/android.permission.INTERNET/)
}
rule allatori_demo_a
{
  meta:
    description = "Allatori demo"
    url         = "http://www.allatori.com/features.html"
    author      = "Ahmet Bilal Can"
    sample      = "7f2f5aac9833f7bdccc0b9865f5cc2a9c94ee795a285ef2fa6ff83a34c91827f"
    sample2     = "8c9e6c7b8c516499dd2065cb435ef68089feb3d4053faf2cfcb2b759b051383c"
  strings:
  $twokeyxor = {
      3a 00 1? 00         //   if-ltz v0, :cond_0
      6e 20 ?? ?? ?4 00   //   invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C
      0a 0?               //   move-result v2
      d8 0? 0? ff         //   add-int/lit8 v3, v0, -0x1
      df 0? 0? ??         //   xor-int/lit8 v2, v2, 0x54
      8e ??               //   int-to-char v2, v2
      50 0? 0? 0?         //   aput-char v2, v1, v0
      3a 0? 0? 00         //   if-ltz v3, :cond_0
      d8 00 0? ff         //   add-int/lit8 v0, v3, -0x1
      6e 20 ?? ?? 34 00   //   invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C
      0a 0?               //   move-result v2
      df 0? 0? ??         //   xor-int/lit8 v2, v2, 0x39
      8e ??               //   int-to-char v2, v2
      50 0? 0? 0?         //   aput-char v2, v1, v3
  }
  condition:
      $twokeyxor
}
rule Androbot_a
{
	meta:
		description = "https://info.phishlabs.com/blog/bankbot-continues-its-evolution-as-agressivex-androbot"
	strings:
		$s1 = "/core/inject.php?type="
		$s2 = "/private/add_log.php"
		$s3 = "/core/functions.php "
	condition:
		2 of ($s*)
}
rule BankBot_a
{
	strings:
	  $ = "cmdline"
	  $ = "receiver_data.php"
	  $ = "set.php"
	  $ = "tsp_tsp.php"
	condition:
		all of them
}
rule BankBot2_a
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
rule could_be_packer_a: packer
{
    meta:
        description = "Generic Packer"
    strings:
        $a = /assets\/.{1,128}\.jar/
        $b = /assets\/[A-Za-z0-9.]{2,50}\.jar/
		$zip_head = "PK"
        $manifest = "AndroidManifest.xml"
    condition:
        ($a or $b) and
		($zip_head at 0 and $manifest and #manifest >= 2)
}
rule PornoLocker_a
{
	condition:
		cuckoo.network.dns_lookup(/soso4ki.ru/) or
		cuckoo.network.dns_lookup(/zapisulka.ru/)
}
rule hydra_a
{
        strings:
                $d2 = "utils.packed.com"
                $d1 = "core.com.packed"
        condition:
                all of them
}
rule detection_a
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
rule koodous_c: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.activity("*.jifenActivity") or
		androguard.activity("*.JFMain")
}
rule gretel_ibingo_launcher3_a
{
	meta:
		description = "com.ibingo.launcher3"
		sha = "7dda8481973cec79416c9aa94d2176bc"
	strings:
		$a_1 = "sdk.loveota.com" fullword
        $a_2 = "alter.sbingo.net.cn" fullword
	condition:
		all of ($a_*)
}
rule sorter_a: official
{
	condition:
		cuckoo.network.dns_lookup(/datace/) or
		cuckoo.network.dns_lookup(/www.mmmmmm/) or 
		cuckoo.network.dns_lookup(/fb.vi/) or 
		cuckoo.network.http_request(/cgi-bin-py\/ad_sdk\.cgi/) or
		cuckoo.network.http_request(/\.zpk/) or
		cuckoo.network.http_request(/\.ziu/) or
		cuckoo.network.http_request(/\/Load\/regReportService/) or 
		cuckoo.network.http_request(/\/Load\/regService/)
}
rule BitcoinAddress_a
{
    meta:
        description = "Contains a valid Bitcoin address"
        author = "Didier Stevens (@DidierStevens)"
    strings:
		$btc = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,33}\b/
    condition:
        any of them
}
rule allatoristrong_a: obfuscator
{
  meta:
    description = "Allatori"
  strings:
    $s = "ALLATORI" nocase
	$n = "ALLATORIxDEMO"
  condition:
    $s and not $n
}
rule Anubis_a
{
        strings:
                $swap = { 48 0? 03 0? 48 0? 03 0? 4f 0? 03 0? 4f 0? 03 0? 0f 0? }
        condition:
                #swap == 1
}
rule Android_Buhsam_hunt_a
{
	meta:
		description = "This rule detects the Android Buhsam apk"
		sample = "4bed89b58c2ecf3455999dc8211c8a7e0f9e8950cb9aa83cd825b8372b1eaa3d"
	condition:
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.BATTERY_STATS/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		androguard.permission(/android.permission.CAMERA/) and
		androguard.permission(/android.permission.READ_CALENDAR/) and
		androguard.permission(/android.permission.READ_CALL_LOG/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/com.android.browser.permission.READ_HISTORY_BOOKMARKS/)
}
rule miner_a: coinminer
{
	meta:
		    description = "Coinhive"
	strings:
	    $miner = "https://coinhive.com/lib/coinhive.min.js" nocase
	    $miner1 = "https://coin-hive.com/lib/coinhive.min.js" nocase
	    $miner2 = "new.CoinHive.Anonymous" nocase
	    $miner3 = "https://security.fblaster.com" nocase
	    $miner4 = "https://wwww.cryptonoter.com/processor.js" nocase
	    $miner5 = "https://jsecoin.com/server/api/" nocase
	    $miner6 = "https://digxmr.com/deepMiner.js" nocase
	    $miner7 = "https://www.freecontent.bid/FaSb.js" nocase
		$miner8 = "htps://authedmine.com/lib/authedmine.min.js" nocase
	    $miner9 = "https://www.bitcoinplus.com/js/miner.js" nocase
	    $miner10 = "https://www.monkeyminer.net" nocase
	condition:
	    any of them
}
rule redalert_a {
	strings:
		$string_1 = /http:\/\/\S+:7878/
		$string_2 = /wroted data base64/
		$string_3 = /templates_names/
	condition:
		1 of ($string_*)
}
rule tarambuka_a
{
	meta:
		description = "This rule detects tarambuka spyware"
		sample = "2a1da7e17edaefc0468dbf25a0f60390"
	strings:
		$a_1 = "twtr.db"
		$a_2 = "hotml.db"
		$a_3 = "skdb.db"
		$a_4 = "vbrmsg.db"
		$a_5 = "whappdbcp.db"
		$a_6 = "MessageSenderService#oncreate"
		$a_7 = "MessageSenderTask#work"
		$a_8 = "PhoneCallSpyListener#sendRecording"
		$a_9 = "SystemAppManager#makeAppSystemApp"
	condition:
		all of ($a_*)
}
rule test_a: BankBot
{
	meta:
		description = "This rule detects the bankbot app based on various info"
		sample="a607a9903b0101bb1ed87381a6f339f83e721555e9355f889798e7b0df28d3cb"
		sample="f61e3e022cafe04add649eab9173317440845bdbc022060225f3c6d4b2e9d4a1"
		sample="d32d98751178ce0a307254a989d1d26c5601abc1b4ea092b1cb5dd470b48bb32"
		sample="f967498ad1623f631356f5a3de2e958cd2794c653218fb8d1828b4be43069e2e"
		sample="4debd811501958491a44f75d1c116d5ac4276bd1f88d22f81e33fcfff4af2c64"
		sample="537e0e9d762ab89f6607ed31fd407142909c652958f4522bf8b1a9958b3c10de"
		sample="3035dde4fa98cba19591808a6f0c2e64f062cb0210350592b72e7a1d8d27710f"
		sample="a558d2d3e786f9ad00c6329056b84ac007578e422e47b56c7f4a6028abbedbdf"
		sample="a3f8e8dc01b620f5ef1da9faa57bf691247f4c9e153b764ec1296f94403c2caa"
		sample="37292ab423ef462b4df34e84116f85f1d0fcf8f8095045170c332cd7164fdda3"
		sample="b42722eb3be50b74d025055165fc0fa84020df11449062dab2f64621965cb776"
		sample="929d57342c0e97eb225a95e18c6f3045862ae54948528d22b93954876b92dd3a"
	strings:
		$a = "http://5.45.73.20/api/?id=1" nocase
		$c2_1 = "/private/tuk_tuk.php" nocase
		$c2_2 = "/private/add_log.php" nocase
		$c2_3 = "/private/set_data.php" nocase
		$c2_4 = "activity_inj" nocase
	condition:
		2 of ($c2_*) or
		$a or androguard.permission(/android.permission.CALL_PHONE/) 
		or androguard.permission(/android.permission.READ_CONTACTS/)
		or androguard.permission(/android.permission.READ_PHONE_STATE/)
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
rule koodous_d: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "BZWBK mobile"
	condition:
		androguard.package_name(/BZWBK/) or $a
}
rule Xavier_a
{
	meta:
		description = "Picks up samples with Xavier defined activity"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.activity(/xavier.lib.XavierActivity/i)
}
rule whatever_a
{
	meta:
		description = "This rule detects something"
	condition:
		androguard.app_name(/BZWBK/) or 
		androguard.app_name("BZWBK") or 
		androguard.app_name(/bzwbk/) or
		androguard.app_name("bzwbk") or
		androguard.app_name(/BZWBK24/) or
		androguard.app_name(/bzwbk24/) or
		androguard.app_name(/BZWBK24 mobile/) or
		androguard.app_name("BZWBK24 mobile") or
		androguard.app_name(/Santander/) or
		androguard.app_name("Santander")
}
rule allatori_commercial_a
{
    strings:
    $stacktracexor = {
        0a 00               //   move-result v0
        23 05 ?? ??         //   new-array v5, v0, [C
        d8 00 00 ff         //   add-int/lit8 v0, v0, -0x1
        01 13               //   move v3, v1
        01 02               //   move v2, v0
        3b 00 08 00         //   if-gez v0, :cond_1
        22 00 ?? ??         //   new-instance v0, Ljava/lang/String;
        70 20 ?? ?? 50 00   //   invoke-direct {v0, v5}, Ljava/lang/String;-><init>([C)V
        11 00               //   return-object v0
        d8 06 02 ff         //   add-int/lit8 v6, v2, -0x1
        6e 20 ?? ?? 28 00   //   invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C
        0a 00               //   move-result v0
        6e 20 ?? ?? 34 00   //   invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C
        0a 07               //   move-result v7
        b7 70               //   xor-int/2addr v0, v7
        df 00 00 ??         //   xor-int/lit8 v0, v0, 0x35
        8e 00               //   int-to-char v0, v0
        50 00 05 02         //   aput-char v0, v5, v2
        3a 06 ea ff         //   if-ltz v6,
        6e 20 ?? ?? 68 00   //   invoke-virtual {p0, v6}, Ljava/lang/String;->charAt(I)C
        0a 00               //   move-result v0
        6e 20 ?? ?? 34 00   //   invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C
        0a 02               //   move-result v2
        b7 20               //   xor-int/2addr v0, v2
        df 00 00 ??         //   xor-int/lit8 v0, v0, 0x6
        8e 07               //   int-to-char v7, v0
        d8 02 06 ff         //   add-int/lit8 v2, v6, -0x1
        d8 00 03 ff         //   add-int/lit8 v0, v3, -0x1
        50 07 05 06         //   aput-char v7, v5, v6
        3b 00 03 00         //   if-gez v0,
        01 10               //   move v0, v1
    }
    condition:
        $stacktracexor
}
rule aamo_str_enc_a: obfuscator
{
  meta:
    description = "AAMO (String decryption function only)"
    author = "P0r0"
    url = "https://github.com/necst/aamo"
  strings:
    $opcodes = {
        22 ?? ?? ??
        12 22
        1a ?? ?? ??
        71 ?? ?? ?? ?? ??
        0c 02
        71 ?? ?? ?? ?? ??
        0c 03
        6e ?? ?? ?? ?? ??
        0c 02
        1a ?? ?? ??
        70 ?? ?? ?? ?? ??
        71 ?? ?? ?? ?? ??
        0c 04
    }
    $a = { 00 0f 63 6f 6e 76 65 72 74 54 6f 53 74 72 69 6e 67 00 } // convertToString
    $b = { 00 14 67 65 74 53 74 6f 72 61 67 65 45 6e 63 72 79 70 74 69 6f 6e 00 } //getStorageEncryption
  condition:
    $opcodes and
    all of ($a, $b)
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
rule koodous_e: official
{
	meta:
		description = "Appdome"
	strings:
		$ = "APPDOME_INTERNAL_GOOD_FSQUEUE"
		$ = "res/drawable/splash_appdome.png"
		$ = "_appdome_splash"
		$ = "AppdomeInternalAppdomeSSOMessage"
		$ = "AppdomeSecurityAlert"
		$ = "APPDOME_INTERNAL_EXPIRE_ON_POLICY"
		$ = "X-APPDOME-MARKEDr"
		$ = "(AppdomeError)"
		$ = "/efs/libloader_cache_android/"
		$ = "/ANTAMP__EFS__SPLASH__EVENTS__FAKE_JNIONLOAD"
	condition:
		any of them
}
private global rule whatever2
{
	condition:
		androguard.app_name(/a/) or
		androguard.app_name(/b/) or
		androguard.app_name(/c/) or
		androguard.app_name("Materialize Your App")
}
rule aamo_str_enc_nop_a: obfuscator
{
  meta:
    description = "AAMO (String decryption function + interleaved NOPs)"
    author = "P0r0"
    url = "https://github.com/necst/aamo"
    example1 = "c1ef860af0e168f924663630ed3b61920b474d0c8b10e2bde6bfd3769dbd31a8"
    example2 = "eb0d4e1ba2e880749594eb8739e65aa21b6f7b43798f04b6681065b396c15a78"
  strings:
    $opcodes = {
        22 ?? ?? ?? 
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 )
        12 22
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        1a ?? ?? ??
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        71 ?? ?? ?? ?? ??
        0c 02
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        71 ?? ?? ?? ?? ??
        0c 03
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        6e ?? ?? ?? ?? ??
        0c 02
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        1a ?? ?? ??
        ( 00 00 | 00 00 00 00 | 00 00 00 00 00 00 ) 
        70 ?? ?? ?? ?? ??
        71 ?? ?? ?? ?? ??
        0c 04
    }
    $a = { 00 0f 63 6f 6e 76 65 72 74 54 6f 53 74 72 69 6e 67 00 } // convertToString
    $b = { 00 14 67 65 74 53 74 6f 72 61 67 65 45 6e 63 72 79 70 74 69 6f 6e 00 } //getStorageEncryption
  condition:
    $opcodes and
    all of ($a, $b)
}
rule koodous_f: official
{
	meta:
		description = "ByteGuard"
	strings:
		$a = "Apple LLVM version 6.0.0 (ByteGuard 0.9.3-af515063)"
		$c =  "(ByteGuard 0"
	condition:
		any of them
}
rule aamo_a: obfuscator
{
  meta:
    description = "AAMO"
    author = "P0r0"
    url = "https://github.com/necst/aamo"
    backup_url = "https://github.com/P0r0/aamo"
    example1 = "c1ef860af0e168f924663630ed3b61920b474d0c8b10e2bde6bfd3769dbd31a8"
    example2 = "eb0d4e1ba2e880749594eb8739e65aa21b6f7b43798f04b6681065b396c15a78"
    example3 = "b1e20bf3bdc53972424560e20c6d9ad12e5e47b8ed429a77f4ba5ff6cb92cb27"
    example4 = "82a570c272579aacdc22410e152f4519738f4e0ececa84e016201c33ad871fa6"
  strings:
    $a = { 00 0f 63 6f 6e 76 65 72 74 54 6f 53 74 72 69 6e 67 00 } // convertToString
    $b = { 00 14 67 65 74 53 74 6f 72 61 67 65 45 6e 63 72 79 70 74 69 6f 6e 00 } //getStorageEncryption
  condition:
    $a and $b
}
rule koodous_g: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a1 = /lib\/[x86\_64|armeabi\-v7a|arm64\-v8a|x86]\/libapkprotect\.so/
		$a2 = "assets/apkprotect.bin"
		$a3 = "assets/apkprotect/classes.dex.bin"
		$a4 = "apkprotect-build.properties"
		$v1  = "Protected-by: ApkProtector 6.5"
		$v2  = "Protected-by: ApkProtector 6.4"
		$v3  = "Protected-by: ApkProtector 6."
	condition:
		1 of ($v*) and 2 of ($a*)
}
rule aamotest_a
{
	meta:
		description = "aamo obfuscator"
		author = "P0r0"
		example = "c1ef860af0e168f924663630ed3b61920b474d0c8b10e2bde6bfd3769dbd31a8"
		example2 = "eb0d4e1ba2e880749594eb8739e65aa21b6f7b43798f04b6681065b396c15a78"
		example3 = "b1e20bf3bdc53972424560e20c6d9ad12e5e47b8ed429a77f4ba5ff6cb92cb27"
		example4 = "82a570c272579aacdc22410e152f4519738f4e0ececa84e016201c33ad871fa6"
	strings:
	$a = { 00 0f 63 6f 6e 76 65 72 74 54 6f 53 74 72 69 6e 67 00 } // convertToString 
	$b = { 00 14 67 65 74 53 74 6f 72 61 67 65 45 6e 63 72 79 70 74 69 6f 6e 00 } //getStorageEncryption
	condition:
		$a and $b
}
rule appguard_kr_a: packer
{
  meta:
    description = "AppGuard (TOAST-NHNent)"
    url         = "https://docs.toast.com/en/Security/AppGuard/en/Overview/"
    url2        = "https://www.toast.com/service/security/appguard"
    sample      = "80ac3e9d3b36613fa82085cf0f5d03b58ce20b72ba29e07f7c744df476aa9a92"
	strings:
    $a1 = "assets/classes.jet"
    $a2 = "assets/classes.zip"
    $a3 = "assets/classes2.jet"
    $a4 = "assets/classes2.zip"
    $a5 = "assets/classes3.jet"
    $a6 = "assets/classes3.zip"
    $b1 = "lib/armeabi-v7a/libloader.so"
    $b2 = "lib/x86/libloader.so"
    $b3 = "lib/armeabi-v7a/libdiresu.so"
    $b4 = "lib/x86/libdiresu.so"
    $c1 = "assets/m7a"
    $c2 = "assets/m8a"
    $c3 = "assets/agconfig"    //appguard cfg?
    $c4 = "assets/agmetainfo"
  condition:
    2 of ($a*) and 1 of ($b*) and 1 of ($c*)
	}
rule chornclickers_a: packer
{
  meta:
    description = "Custom Chinese 'ChornClickers'"
    url         = "https://github.com/rednaga/APKiD/issues/93"
    example     = "0c4a26d6b27986775c9c58813407a737657294579b6fd37618b0396d90d3efc3"
  strings:
    $a = "libhdus.so"
    $b = "libwjus.so"
  condition:
    all of them
}
rule joker_camera_a: official
{
	condition:
		(androguard.app_name(/camera/) or
		androguard.app_name(/wallpaper/) or
		androguard.app_name(/game/)) and
		androguard.permission(/PHONE_STATE/) and
		androguard.permission(/CHANGE_WIFI_STATE/)
}
rule chornclickers_b: packer
{
  meta:
    description = "Custom Chinese 'ChornClickers'"
    url         = "https://github.com/rednaga/APKiD/issues/93"
    example     = "0c4a26d6b27986775c9c58813407a737657294579b6fd37618b0396d90d3efc3"
  strings:
    $a = "lib/armeabi/libhdus.so"
    $b = "lib/armeabi/libwjus.so"
  condition:
    all of them
}
rule koodous_h: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
	strings:
		$a = {33 35 2e 31 39 38 2e 31 39 37 2e 31 31 39 0a}
		$b = {33 35 2e 31 39 38 2e 31 39 37 2e 31 31 39 3a 38 30 38 30 2f 61 64 73 73 65 72 76 65 72 2d 76 33 2f 63 6c 69 65 6e 74 5f 63 6f 6e 66 69 67}
	condition:
		$a or $b
}
rule fortnite_appclone_a
{
	meta:
		description = "This rule detects new Fortnite malicious apps"
		sample = "2a1da7e17edaefc0468dbf25a0f60390"
	strings:
		$a_1 = "StealthMode"
		$a_2 = "onStartCommand"
		$a_3 = "ShowOnLockScreen"
		$a_4 = "The original WhatsApp"
	condition:
		all of ($a_*)
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
rule Android_Trojan_ChatStealer_a
{
	meta:
		description = "This rule will be able to tag all Android_Trojan_ChatStealer samples"
		hash_1 = "79fecbdeeb6a4d31133359c4b8ecf9035ddc1534fcfa6c0d51d62c27d441a6ad"
		hash_2 = "c3544ddb175689cf3aadc5967f061594c210d78db45b3bb5925dedf3700ad4f7"
		hash_3 = "920f18c5ffb59856deccf2d984ab07793fefeea9a5a45d1e8a94a57da9d2347c	"
		author = "Jacob Soo Lead Re"
		date = "01-July-2018"
	condition:
		androguard.service(/nine\.ninere/i)
		and androguard.receiver(/seven\.PhonecallReceiver/i) 
		and androguard.receiver(/eight\.eightre/i) 
		and androguard.permission(/com\.android\.browser\.permission\.READ_HISTORY_BOOKMARKS/i)
}
rule koodous_i: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$ = "OpenSSL 1.0.1"
		$ = "OpenSSL 1.0.0"
	condition:
		any of them
}
rule adwind_a
{
	meta:
		description = "This rule detects effected applications by adwind"
		strings: 
		$a = "load/stub.adwind"
		$b = "plugins/AdwindServer.classPK"
		$c = "plugins/AdwindServer.classuS]w"
		condition:
		all of them
}
rule LokiBot_a
{
	meta:
		description = "This rule will be able to tag all LokiBot samples"
		refernces = "https://www.threatfabric.com/blogs/lokibot_the_first_hybrid_android_malware.html"
		hash_1 = "1979d60ba17434d7b4b5403c7fd005d303831b1a584ea2bed89cfec0b45bd5c2"
		hash_2 = "a10f40c71721668c5050a5bf86b41a1d834a594e6e5dd82c39e1d70f12aadf8b"
		hash_3 = "86ffe2fa4a22e08c134b2287c232b5e46bd3f775274d795b1d526b6340915b5c	"
		author = "Jacob Soo Lead Re"
		date = "30-October-2017"
	condition:
		androguard.service(/CommandService/i)
		and androguard.receiver(/Boot/i) 
		and androguard.receiver(/Scrynlock/i) 
		and androguard.permission(/android\.permission\.BIND_DEVICE_ADMIN/i)
		and androguard.filter(/android\.app\.action\.DEVICE_ADMIN_ENABLED/i) 
		}
rule jiagu_apktoolplus_a: packer
{
    meta:
        description = "Jiagu (ApkToolPlus)"
        sample      = ""
        url         = ""
    strings:
        $a = "assets/jiagu_data.bin"
        $b = "assets/sign.bin"
        $c = "libapktoolplus_jiagu.so"
    condition:
        all of them
}
rule POB_1_a
{
	meta:
		description = "Detects few MyPleasure app"
	condition:
		(androguard.service(/ch.nth.android.contentabo.service.DownloadAppService/))
}
rule PimentoRoot_a: rootkit
{
	condition:
		androguard.url(/http:\/\/webserver\.onekeyrom\.com\/GetJson\.aspx/)
}
rule koodous_j: official
{
	meta:
		description = "biubiubiu"
		sample = "7c88ad48ec5501e65335bceafd703b5c514b31adc52405fc5053b2e08a722ff1"
	strings:
		$str_1 = "01dfbd6a899b6446"
		$str_3 = "rkk021848979234 "
	condition:
		1 of ($str_*)
		or androguard.activity(/\.views\.activities\.BankActivity/)
}
rule Adware_Ashas_a
{
	meta:
		description = "Adware campaign on Google Play"
		url = "https://www.welivesecurity.com/2019/10/24/tracking-down-developer-android-adware/"
		sample = "c1c958afa12a4fceb595539c6d208e6b103415d7"
	strings:
		$a = "aHR0cDovLzM1LjE5OC4xOTcuMTE5OjgwODAvYWRzc2VydmVyLXYzL2NsaWVudF9jb25maWc="
		$f1 = "ALARM_SCHEDULE_MINUTES" fullword
		$f2 = "CODE_CLIENT_CONFIG" fullword
		$f3 = "FULL_ID" fullword
		$f4 = "intervalService" fullword
	condition:
		$a or all of ($f*)
}
rule iHandy_a
{
	meta:
		description = "Detects apps created by/conntected to iHandy"
	condition:
		cuckoo.network.dns_lookup(/appcloudbox.net/)
}
rule DOGlobal_a
{
	meta:
		description = "Evidences of DO global advertisement library / Adware "
	condition:
		cuckoo.network.dns_lookup(/do.global/) or cuckoo.network.dns_lookup(/do-global.com/) or cuckoo.network.dns_lookup(/ad.duapps.com/)
}
rule Banks_Strings_inno_a {
	strings:
		$string_1 = /innotec\.security/
	condition:
		1 of ($string_*)
}
rule oneplus_a: UnauthReboot
{
	meta:
		description = "On Oxygen OS 9 this App allows other apps to reboot the device without any user interaction"
		source = "https://twitter.com/deletescape/status/1186644224986566660"
	condition:
		androguard.package_name("cn.oneplus.nvbackup") and
		androguard.activity(/NvSyncRebootActivity/i)
}
rule whatsapp_a:fake
{
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}
rule king_games_a:fake
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
		and not androguard.certificate.sha1("F22BD3F8C24AB1451ABFD675788B953C325AB550")
}

rule instagram_a:fake
{
	condition:
		androguard.app_name("Instagram")
		and not androguard.certificate.sha1("C56FB7D591BA6704DF047FD98F535372FEA00211")
}
rule android_joker_a {
    strings:
        $net = { 2F6170692F636B776B736C3F6963633D } // /api/ckwksl?icc=   
        $ip = "3.122.143.26"
    condition:
        $net or $ip 
}
rule android_joker_b {
    strings:
        $c = { 52656D6F746520436C6F616B } // Remote Cloak
        $cerr = { 6E6574776F726B2069737375653A20747279206C61746572 } // network issue: try later
        $net = { 2F6170692F636B776B736C3F6963633D } // /api/ckwksl?icc=
        $ip = { 332E3132322E3134332E3236 } // 3.122.143.26     
    condition:
        ($c and $cerr) or $net or $ip 
}
rule koodous_k: official
{
	meta:
		description = "First rule used to detect certain permissions"
	condition:
		androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
}
rule koodous_l: official
{
	condition:
		androguard.url(/abcdserver\.com/) 
}
rule koodous_m: official
{
	meta:
		description = "First rule used to detect certain permissions"
	condition:
		androguard.permission(/android.permission.INTERNET/)
}
rule koodous_n: official
{
	meta:
		description = "First rule used to detect certain permissions"
	condition:
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/)
}
rule ZoopOneSDKTracker_a
{
	meta:
		description = "All Zoop One SDK Apps"
	condition:
		androguard.activity("sdk.zoop.one.offline_aadhaar.zoopActivity.ZoopConsentActivity") or
		androguard.activity("one.zoop.sdkesign.esignlib.qtActivity.QTApiActivity")
}
rule QuaggaSDKTrackerActivity_a
{
	meta:
		description = "All Quagga SDK Apps"
	condition:
		androguard.activity("quagga.com.sdk.ConsentActivity") or
		androguard.activity("com.aadhaarapi.sdk.gateway_lib.qtActivity.AadhaarAPIActivity")
}
rule zipnach_detect_a
{
	meta:
		description = "This rule detects ZIPNach powered apps"
	strings:
		$a = "http://uat1.zipnach.com"
	condition:
		$a and
		androguard.permission(/android.permission.INTERNET/)		
}
rule bbps_detect_a
{
	meta:
		description = "This rule detects BBPS apps"
	strings:
		$a = "http://bbps.org/schema"
		$b = "bbps/BillFetchRequest/1.0/"
		$c = "bbps/BillPaymentRequest/1.0"
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)		
}
rule bancocam_a {
	strings:
		$string_1 = /bancocaminos/
		$string_2 = /onboardingcaminos/
		$string_3 = /lineacaminos/
		$string_4 = /onboardingcaminos/
		$string_5 = /caminosontime/
	condition:
		any of them
}
rule trojanSMS_a
{
	meta:
		description = "This rule detects trojan SMS"
		sample = "ff8ccead81eca2154cf9e891e15f52c8a154ea3aba5e62498b11fb843135837f"
		source = "http://pastebin.com/rLPux7ts"
	strings:
		$d = "com.android.install"
	condition:
		all of them
}
rule NativeCode_a
{
    meta:
    	author = "packmad - https://twitter.com/packm4d"
		date = "2019/11/25"
		description = "This rule detects APKs containing native libs"
    strings:
        $lib_arm = /lib\/arm(eabi|64)-v[0-9a-zA-Z]{2}\//
        $lib_x86 = /lib\/x86(_64)?\//
		$lib_ass = /assets\/[!-~]+\.so/
    condition:
        1 of ($lib_*)
		}
rule starsWallpaper_jan2020_a
{
	meta:
		description = "This rule detects Adware malware discussed in the blog below"
		blog = "https://www.evina.fr/a-malware-rises-to-the-top-applications-in-google-play-store/"
	strings:
		$a1 = "loadLibrary"
    	$a2 = "kkpf"
    	$a3 = "com.sstars.walls"
	condition:
        all of ($a*)
}
rule digitimeBackdoor_a
{
	meta:
		description = "detects the Digitime backdoor"
	strings:
		$intf = "android.app.ILightsService"
		$internel = "com.android.internel.slf4j"
		$uid1 = "uisTeOpCk"
		$uid2 = "iWoPZrScPM1IeF"
		$sv1 = "orgslfaM"
		$sv2 = "orgslfyP"
		$sv3 = "orgslfpb"
		$svName = "fo_sl_enhance"
	condition:
		any of them
}
rule frida_a: anti_hooks
{
	strings:
		$a = "frida-gum"
		$b = "frida-helper"
		$c = "re.frida.HostSession10"
		$d = "AUTH ANONYMOUS 474442757320302e31\\r\\n"
		$e = "re.frida"
		$f = "00 4C 49 42 46 52 49 44 41 5F 41 47 45  4E 54 5F 31 2E 30 00" // "LIBFRIDA_AGENT_1.0"
		$g = "00 66 72 69 64 61 5F 61 67 65 6E 74 5F 6D 61 69 6E 00" // "frida_agent_main"
		$h = "00 66 72 69 64 61 00" // "frida"
	condition:
		any of them
}
rule digitimeTest_a
{
	meta:
		description = "Test to detect Digitime malware"
	strings:
		$key1 = "Ti92T_77Zij_MiTik"
		$key2 = "HiBox_5i5j_XiMik"
		$key3 = "Ti92R_37Rak_AiTia"
		$key4 = "HsTi67_AuIs39_Ka23"
		$key5 = "HsTi67_Ka23"
		$fnv = "FindNewViewsion"
		$dtInfo = "com.dtinfo.tools"
	condition:
		(androguard.receiver(/Rvc$/) and androguard.service(/Svc$/)) or (any of ($key*)) or $fnv or $dtInfo
}
rule test_rule_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a ="yywvdeuznmksaqrrgbknzgzhtycwpzcoyuzmibagol"
	condition:
		androguard.app_name("Chrome") and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED"/) and
		$a 
}
rule BITTER_a
{
	meta:
		description = "This rule detects BITTER"
		sample = "7ad793b2c586b19753245fc901c3d087ef330804ab1836acba1e1eaaccfd5fb8 "
	condition:
		androguard.package_name("com.secureImages.viewer.SlideShow")
}
global rule SuspPerm
{
   condition:
		androguard.permissions_number > 5 and
		androguard.permission(/(SEND|WRITE)_SMS/)
}
rule DisruptiveAds_a
{
	meta:
		description = "This rule detects apps that use distruptive ads"
	strings:
		$susp_string1 = "onBackPressed"
		$susp_string2 = "doubleBackToExitPressedOnce"
	condition:
		$susp_string1 or $susp_string2
}
rule DisruptiveAds_b
{
	meta:
		description = "This rule detects apps that use distruptive ads"
	strings:
        $susp_string1 = "onBackPressed"
        $susp_string2 = "doubleBackToExitPressedOnce"
	condition:
      $susp_string1 or $susp_string2
}
rule mspy_a {
    condition:
        androguard.package_name("android.sys.process") or androguard.certificate.sha1("7FFE6DA96346FEE822E1F791176CD6970A1DC770") or androguard.package_name(/.mspy./) or androguard.package_name("system.framework") or androguard.certificate.sha1("3930B621F30D13D24692CBBBBC67C59F92F1C9BD") or androguard.url(/www.mspyonline.com/)
}
rule onetopspy_a {
    condition:
        androguard.package_name("com.topspy.system") or androguard.certificate.sha1("656CD7890ED79CE8570D1B7156C31958D5AC1606") or androguard.permission(/com.topspy.system.permission/) or androguard.url(/1topspy\.com/)
}
rule mobiispy_a {
    condition:
        androguard.package_name("com.mobiispy.system") or androguard.url(/mobiispy.com/) or androguard.certificate.sha1("3B167CAE3F1EE3C27DA411DF1290C4CDBA41A633") or androguard.url(/www\.MobiiSpy\.com/) or androguard.certificate.sha1("0208CDD00216157F36DCF7FC2567C5263D8AA682")
}
rule hellospy_a {
    condition:
        androguard.certificate.issuer(/HelloSpy LLC/) or androguard.certificate.subject(/HelloSpy LLC/) or androguard.url(/hellospy\.com/) or androguard.package_name("com.hellospy.system") or androguard.certificate.sha1("1EBFFD9FE9463B2ED24582D2846990A5ABEF79B9") or androguard.certificate.issuer(/OU=NOVABAY/) or androguard.certificate.subject(/OU=NOVABAY/)
}
rule maxxspy_a {
    condition:
        androguard.package_name("com.maxxspy.system") or androguard.url(/MaxxSpy\.com/) or androguard.url(/maxxspy\.com/) or androguard.certificate.sha1("6B660EAAEBA47793B7A1278D714669A6612BCA5B")
}
rule nguyen_stalkerware_a {
    condition:
        androguard.certificate.sha1("7F5C0D54A813BA9B87A91420CA2C3DE5E7948F09") or androguard.app_name(/System Service/) or androguard.url(/\:8080\/gcm-demo/) or androguard.certificate.issuer(/John Nguyen/) or androguard.certificate.subject(/John Nguyen/)
}
rule appspy_a {
    condition:
        androguard.package_name("com.atracker.app") or androguard.certificate.sha1("0AD33649F0D0532B5EB0A36A81712962AA79BF54") or androguard.certificate.issuer(/OU=ATracker/) or androguard.certificate.subject(/OU=ATracker/) or androguard.url(/appspy\.net/) or androguard.certificate.issuer(/CN=Allen Hitman/) or androguard.certificate.subject(/CN=Allen Hitman/)
}
rule catwatchful_a {
    condition:
        androguard.package_name("wosc.cwf") or androguard.certificate.issuer(/=catwatchful inc/) or androguard.certificate.subject(/=catwatchful inc/) or androguard.certificate.sha1("9fe876af76cdcb685102a38528a3a732b0872dc6") or androguard.certificate.issuer(/CatWatchful/) or androguard.certificate.subject(/CatWatchful/) or androguard.url(/catwatchful.com/)
}
rule cerberus_a {
    condition:
        androguard.package_name(/com.lsdroid.cerberus/) or androguard.certificate.sha1("BC693B48B7EC988E275CF9E1CDAA1447A31717D9")
}
rule copy9_a {
    condition:
        (androguard.package_name("com.android.system") and androguard.app_name("System Service")) or androguard.certificate.sha1("36E6671BC4397F475A350905D9A649A5ADE97BB2") or androguard.certificate.subject(/iSpyoo Teams/) or androguard.certificate.issuer(/iSpyoo Teams/) or androguard.url(/protocol-a621\.copy9\.com/)
}
rule thetruthspy_a {
    condition:
        androguard.package_name("com.systemservice") or androguard.url(/\.thetruthspy\.com/) or androguard.certificate.sha1("FF8CCD9816B0524A58FBDE1809FB227DBCDFD692")
}
rule ispyoo_a {
    condition:
        androguard.package_name("com.ispyoo") or androguard.certificate.sha1("CBDA86758FBE8E5A6AB805F493AA151B1F2B95F4") or androguard.certificate.issuer(/iSpy Solution/) or androguard.certificate.subject(/iSpy Solution/) or androguard.url(/\.ispyoo.com/) or androguard.certificate.sha1("31A6ECECD97CF39BC4126B8745CD94A7C30BF81C") or androguard.certificate.sha1("5D7B59F3AFB74D86CCD56440F99CA2FC83A23F22")
}
rule easylogger_a {
    condition:
        androguard.package_name("app.EasyLogger") or androguard.certificate.sha1("8F23E1457ADC6189F6ED504A60DF8896FEC6D970") or androguard.package_name("app.ELogger") or androguard.certificate.sha1("35D7CF057BFA5023CE739A725ADA0DA1FD34D1FF")
}
rule flexispy_a {
    condition:
        (androguard.package_name("com.android.systemupdate") and (androguard.app_name("SystemUpdate") or androguard.app_name("com.android.system.service"))) or androguard.certificate.sha1("69B327860EDB531DDFFB1B5DBF0C24245A75F3E4") or androguard.certificate.sha1("93385A087BB5CAB96EAE83A1AF874E0E39B2990F") or androguard.url(/trkps\.com/) or androguard.package_name("com.telephony.android")
}
rule guestspy_a {
    condition:
        androguard.package_name("com.guest") or androguard.certificate.sha1("917bb5b2d40ec40018541784a06285de0f50f60f") or androguard.certificate.issuer(/GuestSpy Solution/) or androguard.certificate.subject(/GuestSpy Solution/) or androguard.url(/.guestspy\.com/)
}
rule highstermobile_a {
    condition:
        androguard.package_name("org.secure.smsgps") or androguard.certificate.sha1("683722A1C629AD5734B93E08ADFAA61775AD196F") or androguard.certificate.subject(/Highsterspyapp/) or androguard.certificate.issuer(/Highsterspyapp/) or androguard.url(/evt17\.com/)
}
rule ddiutilities_a {
    condition:
        androguard.package_name("com.ddiutilities.monitor") or androguard.url(/ddiutilities\.com/)
}
rule hoverwatch_a {
    condition:
        androguard.package_name("com.android.core.monitor.debug") or androguard.certificate.sha1("CC4A78DBE96AC1FA5977E03C97052A9A334113B4") or androguard.url(/hoverwatch\.com/) or androguard.package_name("com.android.core.monitor") or androguard.url(/account\.refog\.com/)
}
rule imonitorspy_a {
    condition:
        androguard.package_name("com.imonitor.ainfo") or androguard.certificate.sha1("BFC4C15E35E3506095B42E2B428E4016B1FFA1AB") or androguard.url(/imonitorsoft\.com/) or androguard.url(/imonitorsoft\.cn/)
}
rule letmespy_a {
    condition:
        androguard.package_name(/pl.lidwin.letmespy/) or androguard.package_name("pl.lidwin.remote") or androguard.certificate.sha1("8F0EAD4F1DA5DAAF8C0F7A51096CECEEF81D0C76") or androguard.certificate.sha1("340E571CB1A64E6EE384D3F8A544681459CF3F5F") or androguard.url(/letmespy\.com/) or androguard.url(/remotecommands\.com/)
}
rule mxspy_a {
    condition:
        androguard.package_name("com.mxspy") or androguard.certificate.sha1("56EF5244378FB6B4EF82D2B9E99BF41F7B97D93A") or androguard.certificate.issuer(/MxSpy LCC/) or androguard.url(/\.mxspy\.com/)
}
rule phonespying_a {
    condition:
        androguard.package_name("com.apspy.app") or androguard.certificate.sha1("D667A33203776F2285EBA3E826CD286356EF05D0") or androguard.certificate.issuer(/PhoneSpying Solution/) or androguard.url(/\.phonespying\.com/)
}
rule repticulus_a {
    condition:
        androguard.package_name("net.vkurhandler") or androguard.package_name("net.system_updater_abs341") or androguard.certificate.sha1("6D0FF787BF4534F1077D1E4BF2E18BA381D97061") or androguard.url(/reptilicus\.net/)
}
rule shadowspy_a {
    condition:
        androguard.package_name("com.runaki.synclogs") or androguard.package_name("com.client.requestlogs") or androguard.certificate.sha1("FE7626A8D3C38FD78EA2A729B39B943BA814F014") or androguard.certificate.sha1("01E49C220A9776D4978C1D28D6C32F86D145B8AE") or androguard.url(/\.shadow-logs\.com/)
}
rule spyhide_a {
    condition:
        androguard.package_name("com.wifiset.service") or androguard.url(/\.spyhide\.com/)
}
rule spyphoneapp_a {
    condition:
        androguard.package_name("com.spappm_mondow.alarm") or androguard.url(/\.spy-phone-app\.com/) or androguard.url(/\.Spy-datacenter\.com/)
}
rule fonetracker_a {
    condition:
        androguard.package_name("com.fone") or androguard.certificate.sha1("B0F639B67819EDBADC73B9FEFF2582FC58B8F115") or androguard.certificate.issuer(/FoneTracker Solution/) or androguard.url(/fonetracker\.com/)
}
rule netspy_a {
    condition:
        androguard.package_name("com.googleplay.settings") or androguard.certificate.sha1("A4E169AAF0068A1FC5F7900B7F59A438B833364C") or androguard.certificate.issuer(/NetSpy LLC/) or androguard.url(/www\.netspy\.net/)
}
rule spyzie_a {
    condition:
        androguard.package_name("com.spyzee") or androguard.package_name("com.ws.scli") or androguard.paimport "androguard"
rule SuspPerm_a
{
   condition:
	 androguard.permission(/(SEND|WRITE)_SMS/)
}
ckage_name("com.ws.sc") or androguard.certificate.sha1("F25D72FCCB84BAF7F73467FC9571024B7E274CA3") or androguard.url(/\.spyzie\.com/) or androguard.url(/\.spyzie\.wondershare\.cn/)
}
rule spymie_a {
    condition:
        androguard.package_name("com.ant.spymie.keylogger") or androguard.certificate.sha1("05B23C7E9156A4C55768DA27936FF2D7AF09BB8F")
}
rule neospy_a {
    condition:
        androguard.package_name("ns.antapp.module") or androguard.certificate.sha1("9ED8DD944D3EB545E1EEEEEC1D8174772CF37C07") or androguard.url(/neospy\.pro/) or androguard.url(/neospy\.net/) or androguard.url(/neospy\.tech/)
}
rule androidmonitor_a {
    condition:
        androguard.package_name("com.ibm.fb") or androguard.certificate.sha1("92EBDB7D7C18A34705A6918B5F327DDB0E8C8452") or androguard.certificate.sha1("558765849658a3821fe4054ed2c1ff6e28b4b8a0") or androguard.url(/\.androidmonitor\.com/)
}
rule DANA_disruptive_adds_a
{
	meta:
		author = "Dana Kalujny"
		description = "This rule is dedicated to find apps with the code pattern: onBackPressed or doubleBackToExitPressedOnce"
		date = "1.2.2020"
	strings:
		$patternA = "onBackPressed"
		$patternB = "doubleBackToExitPressedOnce"
	condition:
		$patternA or $patternB and
		androguard.url("https://play.google.com/store/apps")
}
rule koodous_o: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = ".method public LoadWeb()V"
		$b = ".method private loadWebsite()V"
	condition:
		any of them
}
rule nastyAdware_jan2020_a
{
	meta:
		description = "This rule detects Adware malware discussed in https://labs.bitdefender.com/2020/01/seventeen-android-nasties-spotted-in-google-play-total-over-550k-downloads/" 
	strings:
        $a1 = "clcb.data"
        $a2 = "clcb"
        $b1 = "car.data"
        $b2 = "car3d"
        $c1 = "qrpr.data"
        $c2 = "codeqr"
	condition:
        all of ($a*) or all of ($b*) or all of ($c*)
}
rule FakeSpy_a {
   strings:
      $a = "AndroidManifest.xml"
      $b = "lib/armeabi/librig.so"
      $c = "lib/armeabi-v7a/librig.so"
   condition:
      $a and ($b or $c) and (filesize > 2MB and filesize < 3MB)
}
rule testShopaholicSpyware_jan2020_a
{
	meta:
		description = "This rule detects the a spyawre from  the blog below"
		blog = "https://securelist.com/smartphone-shopaholic/95544/"
		sample = "0a421b0857cfe4d0066246cb87d8768c"
	strings:
			$a1 = "tfile|config.jar"
    		$a2 = "osfields"
    		$a3 = "tpath#fields.css"
    		$a4 = "loadClass"
    		$a5 = "startH1"
	condition:
		all of ($a*)
}
rule Ginp_a
{
	meta:
		description = "This rule detects Ginp Android malware"
	strings:
		$a1 = "IncomingSmsListener"
		$a2 = "PingToServerAndSendSMSService"
		$b1 = "HtmlLoader"
	condition:
		any of ($a*) or any of ($b*)
}
rule Trojan_b: BankBot
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
rule callerapp_a: first
{
	condition:
		(
		androguard.package_name(/monster/) or 
		androguard.package_name(/truck/) or 
		androguard.package_name(/car/) or
		androguard.package_name(/game/)) and
		androguard.permission(/ACCESS_NETWORK_STATE/) and
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/CAMERA/) and
		androguard.permission(/INTERNET/) and
		androguard.permission(/READ_PHONE_STATE/) and
		androguard.permission(/RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/VIBRATE/) and
		androguard.permission(/WAKE_LOCK/)
}
rule brazilianBanker_jan2020_a
{
meta:
		description = "Detects malware listed in https://www.buguroo.com/en/blog/banking-malware-in-android-continues-to-grow.-a-look-at-the-recent-brazilian-banking-trojan-basbanke-coybot. specifically - gover.may.murder samples"
strings:
	$a1 = "ConexaoCentral.php"
	$a2 = "1fs34"
	$a3 = "canDrawOverlays"
condition:
	all of ($a*) 
}
rule android_joker_c {
    strings:
        $c = { 52656D6F746520436C6F616B } // Remote Cloak
        $cerr = { 6E6574776F726B2069737375653A20747279206C61746572 } // network issue: try later
        $net = { 2F6170692F636B776B736C3F6963633D } // /api/ckwksl?icc=
        $ip = { 332E3132322E3134332E3236 } // 3.122.143.26     
    condition:
        ($c and $cerr) or $net or $ip 
}
rule koodous_p: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
	strings:
		$a = /taskAffinity\s*=/
		$b = /allowTaskReparenting\s*=/
		$file = "AndroidManifest.xml"
	condition:
		$file and ($a or $b)
}
rule Android_Trojan_Ransomware_Coin_a
{  
	meta:
		Author = "Anand Singh"
		Date = "04/12/2019"
	strings:
		$a1 = "For correct operation of the program, you must confirm"
		$a2 = "android.app.action.ADD_DEVICE_ADMIN"
		$a3 = "isAutoStartEnabled"
	condition:
		$a1 and $a2 and $a3
}
include "common.yara"
private rule uses_telephony_class : internal
{
  meta:
    description = "References android.telephony.TelephonyManager class"
  strings:
    $a = {00 24 4C 61 6E 64 72 6F 69 64 2F 74 65 6C 65 70 68 6F 6E 79 2F 54
          65 6C 65 70 68 6F 6E 79 4D 61 6E 61 67 65 72 3B 00}
  condition:
    is_dex
    and $a
}
rule checks_device_id_a: anti_vm
{
  meta:
    description = "device ID check"
    sample = "9c6b6392fc30959874eef440b6a83a9f5ef8cc95533037a6f86d0d3d18245224"
  strings:
    $a = {00 0B 67 65 74 44 65 76 69 63 65 49 64 00}
    $b = {00 0F 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 00}
  condition:
    uses_telephony_class
    and all of them
}
rule rosy_strings_plus_manifest_a
{
        meta:
        	description = "description"
		author = "me"
        strings:
            $s4 = "string4"
            $s3 = "string3"
        condition:
            ($s3 or $s4) and 
            ( 
                androguard.receiver("receiver") and
                androguard.filter("filter")
            )
}
on = "This rule detects Android.Bankosy"
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
rule Slempo_a
{
	meta:
		description = "Slempo"
	strings:
		$a = "org/slempo/service/Main" nocase
		$b = "org/slempo/service/activities/Cards" nocase
		$c = "org/slempo/service/activities/CvcPopup" nocase
		$d = "org/slempo/service/activities/CommonHTML" nocase
	condition:
		$a and ($b or $c or $d)
}
rule koodous_q: SlemBunk_Banker
{
	meta:
		description = "Slembunk_jl"
	strings:
		$a = "slem"
		$b = "185.62.188.32"
		$c = "android.app.extra.DEVICE_ADMIN"
		$d = "telephony/SmsManager"
	condition:
		$a and ($b or $c or $d)
}
rule sample_banker_a: banker
{
meta: 
description = "sample rule to detect the malware sample"
thread_level = 2
strings:
$a = "aaAmerican Express The CVC is the four digits located on the front of the card,"
$b = "Keep your Internet Banking and secret authorisation code (SMS) secret."
$c = "XPhone number had an IDD, but after this was not long enough to be a viable phon"
condition:
$a and $b and $c
}
rule slempoBMG_a
{
    meta:
        description = "Regla yara para detectar malware de la familia slempo"
    strings:
        $a = "slempo"
        $b = "content://sms/inbox"
        $c = "DEVICE_ADMIN"
    condition:
        $a and ($b or $c)
}
rule Android_Malware_a: iBank
{
	meta:
		description = "iBank"
	strings:
		$pk = {50 4B}
		$file1 = "AndroidManifest.xml"
		$file2 = "res/drawable-xxhdpi/ok_btn.jpg"
		$string1 = "bot_id"
		$string2 = "type_password2"
	condition:
		($pk at 0 and 2 of ($file*) and ($string1 or $string2))
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
rule slempo_detectado_a
{
        meta:
                description = "Trojan-Banker.Slempo"
        strings:
                $a = "org/slempo/service" nocase
        condition:
                1 of them
}
rule Android_BANKER_JSM_a
{
	meta:
		description = "Esta regla detecta Malware Tipo Banker SlempoService "
	strings:
		$a = "Lorg/slempo/service/MessageReceiver" wide ascii
		$b = "Lorg/slempo/service/MyApplication" wide ascii
		$c = "*Lorg/slempo/service/MyDeviceAdminReceiver" wide ascii
		$d = "Lorg/slempo/service/SDCardServiceStarter" wide ascii
		$e = "org/slempo/service" nocase
		$f = /com.slempo.service/ nocase
		$g = "#Lorg/slempo/service/ServiceStarter" wide ascii
	condition:
		$a or $b or $c or $d or $e or $f or $g
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
rule koodous_r: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name("com.h") and
		androguard.permission(/android.app.action.DEVICE_ADMIN_ENABLED/) 
}
rule sample_b
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
rule Android_BANKER_JSM_b
{
        meta:
                description = "Esta regla detecta Malware Tipo Banker SlempoService"
        strings:
                $a = "Lorg/slempo/service/MessageReceiver" wide ascii
                $b = "Lorg/slempo/service/MyApplication" wide ascii
                $c = "*Lorg/slempo/service/MyDeviceAdminReceiver" wide ascii
                $d = "Lorg/slempo/service/SDCardServiceStarter" wide ascii
                $e = "#Lorg/slempo/service/ServiceStarter" wide ascii
        condition:
                $a or $b or $c or $d or $e
				}
rule geost_a: official
{
	meta:
		description = "This rule detects Trojan Banker"
	condition:
	    androguard.certificate.subject(/C:cn, CN:z, L:shanghai, O:z, ST:shanghai, OU:z/)
}
rule guitarsupersolo_a {
        meta:
            desc = "YARA Rule to detect suspicious activity"
        strings:
            $a = "rooter"
            $b = "0x992c35d3"
        condition:
            $a and $b
    }
rule russianTrojan_a{
	meta:
		description="This rule detects the russian playstore phising apk"
		sample="c220f4f4e0fbeaf4128c15366819f4e61ef949ebc0bd502f45f75dd10544cc57"
		source="https://koodous.com/apks/c220f4f4e0fbeaf4128c15366819f4e61ef949ebc0bd502f45f75dd10544cc57"
	strings:
		$url="http://www.antivirus-pro.us/downloads/list.txt"
		$url2="www.antivirus-pro.us"
		$url3="antivirus-pro.us"
	condition:
		any of ($url*)
}
rule Similar_radio_apps_a: radio
{
	meta:
		description = "Detection of interesting radio apps"
		threat_level = 0
		sample = "aba15a6abbe812ec23018abed9738c85"
	strings:
		$a = "android.permission.ACCESS_COARSE_LOCATION"
		$b = "android.permission.ACCESS_FINE_LOCATION"
		$c = "android.permission.ACCESS_NETWORK_STATE"
		$d = "android.permission.BROADCAST_STICKY"
		$e = "android.permission.GET_TASKS"
		$f = "android.permission.READ_PHONE_STATE"
		$g = "android.permission.WAKE_LOCK"
		$h = "android.permission.RECORD_AUDIO"
		$i = "android.permission.WRITE_EXTERNAL_STORAGE"
		$j = "android.permission.INTERNET"
		$k = "radio"
	condition:
		($a or $b or $c or $d or $e or $f or $g) and $h and $i and $j and $k
}
rule koodous_s: official
{
	meta:
		authors = "Amr Adwan & Jingwen Liu"
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "7bc14c496a29bedbba6cad5a47d4c23f"
	strings:
		$a = "http://cdn.appnext.com/tools/services/4.7.1/config.json"
		$b = "http://imgs1.e-droid.net/android-app-creator/icos_secc/"
		$c = "https://facebook.com/device?user_code=%1$s&qr=1"
	condition:
		any of them
}
rule dinoapp_a: official
{
	meta:
		description = "This rule detects the dinoapp application"
		sample = "708fa5e8d18322f92176ac0121e34dafbda231710e7d2c7b3926326b7108e400"
	condition:
		androguard.package_name("com.BitofGame.DinoSim") or
		androguard.app_name("com.BitofGame.DinoSim") or
		androguard.app_name("dinoapp") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/)
}
rule cleaner_a
{
	meta:
		description = "Determine if apk is a fake cleaner"
		sample = "32741c74508b5efaeada5d68bda3ddf53124331c22dd0b89b5b89647de1ce070"
	condition:
		androguard.app_name("Super Clean Master") and 
		not androguard.certificate.sha1("63f1eae14e454ee2d1ea7923853f93e788dd00e8")
}
rule blockrogue_a: detect
{
	meta:
		description = "Yara rule made for an assignment"
	condition:
		(
		androguard.app_name("Block Rogue") or
		androguard.app_name("Rogue") or
		androguard.app_name("Block")
		) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATUS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATUS/) and
		androguard.min_sdk >= 8 and
        androguard.target_sdk <= 14 
}
rule identity_a
{
	meta:
		authors = "Casper Jol and Christian Steennis"
		description = "Rule to identify apk"
		date = "18-11-2020"
	strings:
		$perm_a = "android.permission.ACCESS_NETWORK_STATE"
		$perm_b = "android.permission.GET_TASKS"
		$perm_c = "android.permission.WAKE_LOCK"
		$perm_d = "android.permission.ACCESS_WIFI_STATE"
		$perm_e = "android.permission.READ_PHONE_STATE"
		$perm_f = "android.permission.BLUETOOTH"
	condition:
		$perm_a and $perm_b and $perm_c and $perm_d and $perm_e and $perm_f 
}
rule detect_a: Dinosim
{
	meta:
		description = "This rule detects the Dinosim application"
		sample = "708fa5e8d18322f92176ac0121e34dafbda231710e7d2c7b3926326b7108e400"
	condition:
		androguard.package_name("com.BitofGame.DinoSim") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("1e8b087dd8a699faa427a12844ba070b2c66218e")
}
rule Reciever_a
{
	meta:
		description = "Rule seeks to detect certain reciever (see PReciever and OReciever in sample) classes in order to detect apps similair to this one."
		sample = "e970b8ab54cf6c1e1c7d06440867ed4e40dfa277cedb38796ac8ae30380df512"
	strings:
		$a = "Receiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
		$b = "Receiver;-><init>()V"
	condition:
		$a and $b and filesize == 471 and (
		androguard.permission(/android.permission.BROADCAST_WAP_PUSH/) 
			or androguard.permission(/android.permission.BROADCAST_SMS/)
		)
}
rule shishiplace_a
{
	meta:
		description = "This  rule detects the shushiplace apk and similar types of apk's."
	condition:
		file.sha265("ab0c364ff6b1678ee85fea0437ff563f51c63332a2cf3ef4c07ac9112dad8deb") or
		(
		androguard.package_name("com.appswiz.shushiplace") and
		androguard.certificate.sha1("678776B603C4D2D44E596F16E08C2E2C1859D208") and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.certificate.sha1("678776B603C4D2D44E596F16E08C2E2C1859D208")
		)
}
rule repackage_a: ESFileExplorer
{
	meta:
		description = "This is a YARA made as an exercise for a security course at the university of Leiden, checking hashes of dropped files found with TotalVirus"
		source = "https://koodous.com/apks/8d2af30355950ad6fbe0bddb94d08146e4a29ec6649996aa6146fc70c5208ab4"
	strings:
		$a = "e6e946529bc1171f6c62168f9e9943613261062373f5c89330e15d9778c5355b"
		$b = "06fd44e4a8268c4b69f873be0daa00de36214b8521673f059700fae638028cda"
		$c = "33cc60e3851c2d813b95b6e2a6405a7e31d76be95de3a1050f03f44c5ee23c09"
		$d = "a7fef32d5e603306b064b2f9d8bb197fc13d9e798ebaa3862e703e479462485a"
		$e = "/data/data/com.estrongs.android.pop/code_cache/secondary-dexes/com.estrongs.android.pop-1.apk.classes2.zip" 
		$f = "/data/data/com.estrongs.android.pop/code_cache/secondary-dexes/com.estrongs.android.pop-1.apk.classes3.zip"
	condition:
		( $a and $b and $c and $d ) or ( $e and $f )
}
rule koodous_t: official
{
	meta:
		description = "This rule detects whether an app is malicious"
	strings:
		$a = "HttpClient;->execute" //Query for a remote server
		$connect_to_url =  "java/net/URL;->openConnection" //connect to an URL
		$developer = "com.atrilliongames" //The package of the developer of the app
	condition:
		$a and $connect_to_url and $developer and androguard.permission(/android.permission.RECORD_AUDIO/) //If an game permission to record your audio and it wants to connect to a remote server, then it's most likely an malicious app.
}
rule Mire_a
{
	meta:
		description = "Mire tools"
		sample = "adc8178e9bcabfdf931583768f3596f2dc3237c8bed0af4c6a869fa43040a78a"
	strings:
		$a = "chenxuan"
		$b = "tbs"
	condition:
		$a and
		$b and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and 
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/)
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
rule silent_banker_b: banker
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
rule silent_banker_c: banker
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
rule silent_banker_d: banker
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
rule silent_banker_e: banker
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
rule silent_banker_f: banker
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
rule silent_banker_g: banker
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
rule silent_banker_h: banker
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
rule Vemnotiba_a:Adware
{
	meta:
		description = "Android.Spy.305.origin WIP"
		sample = "0e18c6a21c33ecb88b2d77f70ea53b5e23567c4b7894df0c00e70f262b46ff9c"
	condition:
		cuckoo.network.dns_lookup(/client\.api-restlet\.com/) and
		cuckoo.network.dns_lookup(/cloud\.api-restlet\.com/)
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
rule FantaSDK_a
{
	meta:
		author = "CP"
		date = "20-May-2017"
		description = "This rule detects the Fanta SDK malware see here http://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out"
	strings:
		$fanta_service = "com.fanta.services"
		$googie= "com.googie"
		$fantastr1 ="fanta\"" nocase
		$fantastr2 ="Fanta v." nocase
	condition:
		$fanta_service or $googie and ( $fantastr1 or $fantastr2 )
}
rule Android_NetWire_a
{
	meta:
		description = "This rule detects the NetWire Android RAT, used to show all Yara rules potential"
		sample = "41c4c293dd5a26dc65b2d289b64f9cb8019358d296b413c192ba8f1fae22533e "
	strings:
		$a = {41 68 4D 79 74 68}
	condition:
		androguard.url(/\?model=/) and $a
		and androguard.permission(/android.permission.ACCESS_FINE_LOCATION/)
and androguard.permission(/android.permission.SEND_SMS/)
and androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/)
and androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)
and androguard.permission(/android.permission.READ_PHONE_STATE/)
and androguard.permission(/android.permission.CAMERA/)
and androguard.permission(/android.permission.RECORD_AUDIO/)
and androguard.permission(/android.permission.WAKE_LOCK/)
and androguard.permission(/android.permission.READ_CALL_LOG/)
and androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
and androguard.permission(/android.permission.INTERNET/)
and androguard.permission(/android.permission.MODIFY_AUDIO_SETTINGS/)
and androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
and androguard.permission(/android.permission.READ_CONTACTS/)
and androguard.permission(/android.permission.READ_SMS/)
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
rule Spy_Banker_a
{
	meta:
		description = "This rule detects the Spy.Banker.BQ"
		sample = "d715e0be04f97bb7679dec413ac068d75d0c79ce35c3f8fa4677fc95cefbfeb8"
	strings:
		$a = "#BEBEBE"
		$b = "Remove MMS"
		$c = "Enter credit card"
		$d = "SELECT  * FROM smsbase"
		$e = "szCardNumverCard"
		$f = "[admintext]"
	condition:
		all of them
}

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
rule fake_market_a: fake android
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
rule fakeInstaller_a
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
rule MazarBot_a
{
	meta:
		description = "This rule detects Android.MazarBot"
		sample = "16bce98604e9af106a70505fb0065babbfc27b992db0c231e691cb1c9ae6377b "
		source = "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"
	strings:
		$string_1 = "assets/armeabi/polipo.mp3"
		$string_2 = "assets/armeabi/polipo_old.mp3"
		$string_5 = "assets/polipo.mp3"
		$string_6 = "assets/polipo_old.mp3"
		$string_9 = "assets/x86/polipo.mp3"
		$string_10 = "assets/x86/polipo_old.mp3"
	condition:
		$string_1 or $string_2  or $string_9 or $string_10  or $string_5 or $string_6
}
rule sms_smspay_a: chinnese
{
	meta:
		description = "smspay chinnese"
		thread_level = 3
		in_the_wild = true
	strings:
		$a = "res/raw/app_id.txt"
		$b_1 = "btNguyenVong3"
		$b_2 = "btNguyenVong2"
		$c_1 = "btTraDiemThi"
		$c_2 = "bjbddhjsy6"
	condition:
		$a and (any of ($b_*)) and (any of ($c_*))
}

rule Trojan_Droidjack_a
{
meta:
author = "https://twitter.com/SadFud75"
condition:
androguard.package_name("net.droidjack.server") or androguard.activity(/net.droidjack.server/i)
}
rule Trojan_Droidjack_b
{
  meta:
      author = "https://twitter.com/SadFud75"
  condition:
      androguard.package_name("net.droidjack.server") or androguard.activity(/net.droidjack.server/i)
}
rule koodous_u: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "8907e44c44753482ca1dd346c8282ae546a554c210dd576a3b1b467c25994c0a"
	strings:
	  $mrat_domain = "fdddt.pw"
	condition:
		$mrat_domain
}

rule GhostFrameWork_EventDex_a
{
	strings:
		$a = "EventDex"
	condition:
		$a		
}
rule basebridge_a
{
	meta:
		description = "A rule to detect Basebridge app"
		sample = "7f8331158501703c5703acaf189bcdd7cb026c14a453a662cb0dfd8bd49a2a45"
		source = "https://www.f-secure.com/v-descs/trojan_android_basebridge.shtml"
	strings:
		$a = "&HasSimCard="
		$b = "&mobilekey="
		$c = "http://service.sj.91.com/AppCenter/index.aspx"
	condition:
		all of them
}
rule koodous_v: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.permission(/android.permission.BIND_DEVICE_ADMIN/)
}
rule koodous_w: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.permission(/android.permission.INSTALL_PACKAGES/)
}
rule lokibot_grotez_a
{
	meta:
		description = "This rule detects the Loki iterration application, used to show all Yara rules potential"
	strings:
		$a = "certificato37232.xyz"
		$b = "47.91.77.112"
	condition:
		any of them
}
rule SMSSpy_a
{
	strings:
		$files_0 = "syedcontacts"
		$files_1 = "allcontacts.txt"
		$files_2 = "tgcontact"
		$files_3 = "tgupload"
	condition:
	  	any of ($files_*) or
		cuckoo.network.dns_lookup(/zahrasa/) or
		androguard.url(/zahrasa/) or
		cuckoo.network.dns_lookup(/tgcontact/) or
		androguard.url(/tgcontact/) or
		cuckoo.network.dns_lookup(/tgupload/) or
		androguard.url(/tgupload/)
}
rule bankingapps_a
{
	strings:
	  $ = "com.ingbanktr.ingmobil"
	  $ = "com.ing.mobile"
	  $ = "au.com.ingdirect.android"
	  $ = "de.ing_diba.kontostand"
	  $ = "com.ing.diba.mbbr2"
	  $ = "com.IngDirectAndroid"
	  $ = "pl.ing.ingmobile"
	condition:
		1 of them
}
rule Banks_Strings_BOI_a {
	strings:
		$string_1 = /boi\.com/
		$string_2 = /365online\.com/
		$string_3 = /businessonline\-boi\.com/
		$string_4 = /bankofireland\.com/
	condition:
		1 of ($string_*)
}
rule koodous_x: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name("/amaq/")
}
rule Ransomware_a
{
	strings:
		$a = "All your files are encrypted"
		$b = "Your phone is locked until payment"
	condition:
		$a or $b	
}
rule videogames_a
{
    condition:
        false
}
rule FakeClashOfClans_a
{
	meta:
		description = "Fake Clash of clans applications"
	condition:
		androguard.app_name(/clash of clans/i) and
		not androguard.certificate.sha1("456120D30CDA8720255B60D0324C7D154307F525")
}
rule Banks_Strings_PermanentTSB_a {
	strings:
		$string_1 = /permanenttsb\.ie/
		$string_2 = /open24\.ie/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_UlsterBank_a {
	strings:
		$string_1 = /digital\.ulsterbank\.ie/
		$string_2 = /ulsterbankanytimebanking\.ie/
		$string_3 = /ulsterbank\.ie/
		$string_4 = /cardsonline\-commercial\.com/
		$string_5 = /bankline\.ulsterbank\.ie/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_KBC_a {
	strings:
		$string_1 = /online\.kbc\.ie/
		$string_2 = /kbc\.ie/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_AIB_a {
	strings:
		$string_1 = /onlinebanking\.aib\.ie/
		$string_2 = /business\.aib\.ie/
		$string_3 = /aib\.ie/
	condition:
		1 of ($string_*)
}
rule JusPayActivity_a
{
	meta:
		description = "All JusPay SDK Apps"
	condition:
		androguard.activity("in.juspay.godel.PaymentActivity")	or
		androguard.activity("in.juspay.juspaysafe.LegacyPaymentActivity")
}
rule Leanback_a: jcarneiro
{
	strings:
		$a = "leanback"
	condition:
		$a	
}
rule EzetapSDKTracker_a
{
	meta:
		description = "All Ezetap SDK Apps"
	condition:
		androguard.activity("com.eze.api.EzeAPIActivity")
}
rule RuPayTracker_a
{
	meta:
		description = "This rule detects RuPay merchant verification"
	strings:
		$a = "https://swasrec.npci.org.in"
		$b = "https://swasrec2.npci.org.in"
		$c = "https://mwsrec.npci.org.in/MWS/Scripts/MerchantScript_v1.0.js"
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)
}
rule CitrusSDKActivity_a
{
	meta:
		description = "All Citrus SDK Apps"
	condition:
		androguard.activity("com.citrus.sdk.CitrusActivity")
}
rule EBSPaymentsSDKActivity_a
{
	meta:
		description = "All EBS Payments SDK Apps"
	condition:
		androguard.activity("com.ebs.android.sdk.PaymentDetailActivity")		
}
rule PayTMSupremeAuthActivity_a
{
	meta:
		description = "All PayTM auth Apps"
	condition:
		androguard.activity("com.one97.supreme.ui.auth.SupremeAuthActivity")
}
rule PhonePeActivity_a
{
	meta:
		description = "All Phonepe SDK Apps"
	condition:
		androguard.activity("com.phonepe.android.sdk.ui.MerchantTransactionActivity") or
		androguard.activity("com.phonepe.android.sdk.ui.debit.views.TransactionActivity")		
}
rule YesBankActivity_a
{
	meta:
		description = "All YesBank UPI SDK"
	condition:
		androguard.activity("com.yesbank.TransactionStatus")
}
rule InstamojoActivity_a
{
	meta:
		description = "All Instamojo SDK Apps"
	condition:
		androguard.activity("com.instamojo.android.activities.PaymentActivity")
}
rule BillDeskPayActivity_a
{
	meta:
		description = "All BillDesk SDK Apps"
	condition:
		androguard.activity("com.billdesk.sdk.QuickPayView")		
}
rule netc_detect_a
{
	meta:
		description = "This rule detects FASTag apps"
	strings:
		$a = "http://npci.org/etc/schema"
	condition:
		($a) and
		androguard.permission(/android.permission.INTERNET/)		
}
rule LotusPaySDKTrackerActivity_a
{
	meta:
		description = "All LotusPay SDK Apps"
	condition:
		androguard.activity("com.lotuspay.library.LotusPay")	
}
rule PayUActivity_a
{
	meta:
		description = "All PayU SDK Apps"
	condition:
		androguard.activity("com.payu.payuui.Activity.PayUBaseActivity")
}
rule MobikwikSDKActivity_a
{
	meta:
		description = "All Mobikwik SDK Apps"
	condition:
		androguard.activity("com.mobikwik.sdk.PaymentActivity")
}
rule AmazonPayINSDKActivity_a
{
	meta:
		description = "All Amazon Pay India Apps"
	condition:
		androguard.activity("amazonpay.silentpay.APayActivity")
}
rule FreechargeINSDKActivity_a
{
	meta:
		description = "All Freecharge India Apps"
	condition:
		androguard.activity("in.freecharge.checkout.android.pay.PayInitActivity")
}
rule UPIPINActivity_a
{
	meta:
		description = "All UPI PIN Activity apps"	
	condition:
		androguard.activity("org.npci.upi.security.pinactivitycomponent.GetCredential")				
}
rule BHIMAadhaarUPITrackerActivity_a
{
	meta:
		description = "All TCS AePS UPI apps"	
	condition:
		androguard.activity("com.tcs.merchant.cags.UPIPaymentFragment")		
}
rule PayTMActivity_a
{
	meta:
		description = "All PayTM SDK Apps"
rule koodous_y: official
{
	strings:
		$ai = "com.google.android.gms.ads.InterstitialAd"
		$b = "co.tmobi.com.evernote.android.job.JobRescheduleService"
	condition:
		1 of them
}
rule evernote_a
{
	strings:
		$a = co.tmobi.com.evernote.android.job.JobRescheduleService
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
rule WhiteBroad_a
{
	meta:
		description = "This rule will be able to tag all the WhiteBroad stealer"
		hash_1 = "4e4a3c71818bbed5a8444c8f3427aabda8387e86576d1594bf30b9dbfe5ae25f"
		hash_2 = "75a7ccc2e9366e32aeeb34981eea0c90f6b0c536bf484d02ac8d3c4acac77974"
		hash_3 = "d8cac1a371a212189f1003340ffc04acecc1c6feeb3437efe06a52fef7ab74c6"
		hash_4 = "66c3d878f4613ab3929c98d9dd5d26c59501e50076c19c437b31ce899ff4a8cc"
		author = "Jacob Soo Lead Re"
		date = "10-December-2018"
	condition:
		androguard.service(/PkgHelper/i)
		and androguard.service(/SimpleWindow/i)
		and androguard.receiver(/KeepReceiver/i) 
		and androguard.receiver(/MessageReceiver/i) 
		and androguard.receiver(/ShowReceiver/i) 
		and androguard.activity(/MainActivity/i) 
}
rule LeegalitySDKTracker_a
{
	meta:
		description = "All Leegality SDK Apps"
	condition:
		androguard.activity("com.leegality.leegality.Leegality")
}
rule koodous_z: official
{
	meta:
		description = "This rule detects the Koodous application, used to show all Yara rules potential"
		sample = "4ad3af0e45727888230eaded3d319445ad60f57102feb33f2a62ef9a5c331e7d"
	strings:
		$a = "Killing all background processes..."
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and $a
}
rule WibmoSDKTrackerActivity_a
{
	meta:
		description = "All Wibmo SDK Apps"
	condition:
		androguard.activity("com.enstage.wibmo.sdk.inapp.InAppInitActivity")
}
rule CoronaVirusTrackerRansomware1_a
{
	meta:
		description = "This rule detects CoronaVirus Tracker ransomware"
		sample = "d1d417235616e4a05096319bb4875f57"
	strings:
		$a1 = "qmjy6.bemobtracks"
		$a2 = "enter decryption code"
		$a3 = "You Phone is Decrypted"
	condition:
		all of ($a*)
}
rule Adware_a
{
	meta:
        description = Adware indicators
	strings:
    	$1 = ""
    	$2 = "&airpush_url="
		$3 = "getAirpushAppId"
		$4 = "Airpush SDK is disabled"
rule Lookout_Monokle_Android_a
{
 meta:
   description = "Rule for Monokle Android samples. Configuration information suggests actor has a presence in Russia. Campaigns appear highly targeted."
   auth = "Flossman - SecInt <threatintel@lookout.com>"
   date = "2018-04-24"
   version = "1.0"
 strings: 
 $dex_file = { 64 65 78 0A 30 33 35 00 }
 $seq_security_update = { 00 20 4C 63 6F 6D 2F 73 79 73 74 65 6D 2F 73 65 63 75 72 69 74 79 5F 75 70 64 61 74 65
2F 41 70 70 3B 00 }
 $str_recs_file = "recs233268"
 $str_sound_rec_fname = "nsr516336743.lmt"
 $str_nexus_6_recording = "Nexus 6 startMediaRecorderNexus"
 $str_next_connect_date_fname = "lcd110992264.d"
 $str_app_change_broadcast = "com.system.security.event.APP_CHANGE_STATE"
 $str_remove_presence_flag_1 = "Android/data/serv8202965/log9208846.txt"
 $str_remove_presence_flag_2 = "Android/data/serv8202965"
 $str_user_dict = "/data/local/tmp/5f2bqwko.tmp"
 $seq_failed_to_read_firefox = { 46 61 69 6C 65 64 20 74 6F 20 72 65 61 64 20 46 69 72 65 66 6F 78 20 42 72 6F 77 73 65 72 20 62 6F 6F 6B 6D 61 72 6B 73 20 66 72 6F 6D 20 }
 $str_firefox_temp_default = "/data/local/tmp/fegjrexkk.tmp"
 $seq_failed_to_read_samsung = { 46 61 69 6C 65 64 20 74 6F 20 72 65 61 64 20 53 61 6D 73 75 6E 67 20 42 72 6F 77 73 65 72 20 62 6F 6F 6B 6D 61 72 6B 73 20 66 72 6F 6D 20 }
 $str_get_bookmarks_api_log = "getBookmarksFromSBrowserApi23"
 $str_samsung_browser_temp = "/data/local/tmp/swbkxmsi.tmp"
 $str_samsung_browser_temp_2 = "/data/local/tmp/swnkxmsh.tmp"
 condition:
 $dex_file and (any of ($seq*) or any of ($str*))
}
rule SuspiciousPermissions_a
{
	meta:
		description = "Yara rule to detect deceptive apps"
	strings:
		$susp_string1 = "onBackPressed"
		$susp_string2 = "doubleBackToExitPressedOnce"
	condition:
		$susp_string1 and $susp_string2		
}
rule AePSMicroATM_a
{
	meta:
		description = "Detect All AePS apps built for MicroATM agents by a platform X"
	condition:
		androguard.url("aepsandroidapp.firebaseio.com")
}
rule FinoPaySDKTrackerActivity_a
{
	meta:
		description = "All Fino SDK Apps"
	condition:
		androguard.activity("com.finopaytech.finosdk.activity.DeviceSettingActivity") or
		androguard.activity("com.finopaytech.finosdk.fragments.BTDiscoveryFragment") or
		androguard.activity("com.finopaytech.finosdk.activity.MainTransactionActivity") or
		androguard.activity("com.finopaytech.finosdk.activity.TransactionStatusActivity")
}
rule iServeUSDKActivity_a
{
	meta:
		description = "All iServeU AePS SDK Apps"
	condition:
		androguard.activity("com.iserveu.aeps.aepslibrary.dashboard.DashboardActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.microatm.MicroAtmActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.WelcomeMATMSdkActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.transaction.ReportActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.transactionstatus.TransactionStatusActivity") or
		androguard.activity("com.iserveu.aeps.aepslibrary.transaction.TransactionReceiptActivity")
}
rule SimplSDKActivity_a
{
	meta:
		description = "All Simpl SDK Apps"
	strings:
		$a = "https://approvals-api.getsimpl.com/my-ip"
		$b = "https://staging-approvals-api.getsimpl.com/api/v2/"
		$c = "https://staging-subscriptions-api.getsimpl.com/api/v3/"
		$d = "https://sandbox-approvals-api.getsimpl.com/api/v2/"
		$e = "https://subscriptions-api.getsimpl.com/api/v3/"
		$f = "https://sandbox-subscriptions-api.getsimpl.com/api/v3/"
	condition:
		androguard.activity("com.simpl.android.zeroClickSdk.view.activity.BaseSimplScreen") or
		androguard.activity("com.simpl.android.sdk.view.activity.BaseSimplScreen") or
		$a or $b or $c or $d or $e or $f
}
rule fanghu_a: official
{
	condition:
		androguard.app_name("fanghu")
}
rule AtomSDKTracker_a
{
	meta:
		description = "All Atom SDK Apps"
	condition:
		androguard.activity("com.qq.e.ads.ADActivity")	
}
rule TencentLocation_a: spy
{
	meta:
		description = "This rule detects apps which use Tencent location service, which may be spyware. Also, many apps which use this are suspicious Chinese apps"
	strings:
		$a1 = /addrdesp/i
		$a2 = /resp_json/i
rule credicorp_a {
	strings:
		$string_1 = /splashscreentest/
		$string_2 = /pacifico.miespacio/
		$string_3 = /pacifico.iwant/
		$string_4 = /bcp.benefits/
		$string_5 = /innovacxion.yapeapp/
		$string_6 = /bcp.bank/
		$string_7 = /bnfc.npdb/
		$string_8 = /coebd.paratiapp/
		$string_9 = /coebd.manyar/
		$string_10 = /innovaxcion.pagafacil/
		$string_11 = /bank.tlc/
		$string_12 = /bo.discounts/
		$string_13 = /bcp.bo.wallet/
		$string_14 = /mobile.credinetweb/
		$string_15 = /mibanco.bancamovil/
		$string_16 = /benefits.mibanco/
		$string_17 = /bederr.mibancoapp/
		$string_18 = /dataifx.credicorp/
		$string_19 = /credicorp19/
		$string_20 = /indisac.link2019/
	condition:
		any of them
}
rule CashFreeSDKTracker_a
{
	meta:
		description = "All CashFree SDK Apps"
	condition:
		( androguard.activity("com.gocashfree.cashfreesdk.CFPaymentActivity") or
		androguard.activity("com.gocashfree.cashfreesdk.CFUPIPaymentActivity") or
		androguard.activity("com.gocashfree.cashfreesdk.AmazonPayActivity") or
		androguard.activity("com.gocashfree.cashfreesdk.GooglePayActivity") or
		androguard.activity("com.gocashfree.cashfreesdk.CFPhonePayActivity"))
}
rule test_CerebrusDecrypted_a
{
	meta:
		description = "This rule, if works, should detected decrypted cerberus apk files" 
	strings:
		$a1 = "patch.ring0.run"
		$a2 = "143523#"
		$a3 = "enabled_accessibility_services"
		$a4 = "android.app.role.SMS"
		$a5 = "device_policy"
		$a6 = "Download Module:"
	condition:
        all of ($a*)
}
rule AtomSDKTracker_b
{
	meta:
		description = "All Atom SDK Apps"
	condition:
		androguard.activity("com.atom.mobilepaymentsdk.PayActivity")		
}
rule algo360_detect_a
{
	meta:
		description = "This rule detects Algo360 Credit Score SDK apps"
	strings:
		$a = "iapi.algo360.com"
		$b = "https://uat.algo360.com:7777"		
	condition:
		($a or $b) and
		androguard.permission(/android.permission.INTERNET/)		
}
private rule upx_elf32_arm_stub : packer
{
  meta:
    description = "Contains a UPX ARM stub"
  strings:
    $UPX_STUB = { 1E 20 A0 E3 14 10 8F E2 02 00 A0 E3 04 70 A0 E3 00 00 00 EF 7F 00 A0 E3 01 70 A0 E3 00 00 00 EF }
  condition:
    $UPX_STUB
}
rule promon_a: packer
{
  meta:
    description = "Promon Shield"
    url         = "https://promon.co/"
    sample      = "6a3352f54d9f5199e4bf39687224e58df642d1d91f1d32b069acd4394a0c4fe0"
  strings:
    $a = "libshield.so"
    $b = "deflate"
    $c = "inflateInit2"
    $d = "crc32"
    $s1 = /.ncc/  // Code segment
    $s2 = /.ncd/  // Data segment
    $s3 = /.ncu/  // Another segment
  condition:
    ($a and $b and $c and $d) and
    2 of ($s*)
}
rule koodous_ba: official
{
	meta:
		description = "This rule detects MobOK Variants"
	strings:
		$a1 = "okyesmobi"
		$a2 = "52.221.7.34"
		$a3 = "45.79.19.59"
		$a4 = "bb.rowute.com"
		$a5 = "koapkmobi.com"
	condition:
		any of them
}
rule Miners_cpuminer_a: coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
	strings:
		$a1 = "MinerSDKRunnable"
		$a2 = "startMiner"
		$a3 = "stop_miner"
		$a4 = "cpuminer_start"
	condition:
		any of them and tag:detected
}
rule Miners_lib_a: coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
	strings:
		$a1 = "libcpuminer.so"
		$a2 = "libcpuminerpie.so"
	condition:
		$a1 or $a2 
}
rule Androidos_js_a: coinminer
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/coin-miner-mobile-malware-returns-hits-google-play/; 		https://twitter.com/LukasStefanko/status/925010737608712195"
		sample = "22581e7e76a09d404d093ab755888743b4c908518c47af66225e2da991d112f0"
		author = "https://koodous.com/analysts/pr3w"
	strings:
		$url = "coinhive.com/lib/coinhive.min.js"
		$s1 = "CoinHive.User"
		$s2 = "CoinHive.Anonymous"
	condition:
		$url and 1 of ($s*)	
}
rule Miner_a_a: coinminer
{
	meta:
		    description = "Coinhive"
			author = "https://koodous.com/analysts/JJRLR"
	strings:
	    $miner = "https://coinhive.com/lib/coinhive.min.js" nocase
	    $miner1 = "https://coin-hive.com/lib/coinhive.min.js" nocase
	    $miner2 = "new.CoinHive.Anonymous" nocase
	    $miner3 = "https://security.fblaster.com" nocase
	    $miner4 = "https://wwww.cryptonoter.com/processor.js" nocase
	    $miner5 = "https://jsecoin.com/server/api/" nocase
	    $miner6 = "https://digxmr.com/deepMiner.js" nocase
	    $miner7 = "https://www.freecontent.bid/FaSb.js" nocase
		$miner8 = "htps://authedmine.com/lib/authedmine.min.js" nocase
	    $miner9 = "https://www.bitcoinplus.com/js/miner.js" nocase
	    $miner10 = "https://www.monkeyminer.net" nocase
	condition:
	    any of them 
}
rule miner_adb_a
{
	meta:
		description = "This rule detects adb miner "
		sample = "412874e10fe6d7295ad7eb210da352a1"
		author = "https://koodous.com/analysts/skeptre"
	strings:
		$a_1 = "/data/local/tmp/droidbot"
		$aa_1 = "pool.monero.hashvault.pro:5555"
		$aa_2 = "pool.minexmr.com:7777"
	condition:
		$a_1 and 
		any of ($aa_*)
}
rule miner_b_a: coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
	strings:
		$a1 = "android-cpuminer/"
		$a2 = "mining.subscribe"
		$url1 = "https://coinhive.com/lib/coinhive.min.js" nocase
		$url2 = "https://coin-hive.com/lib/coinhive.min.js" nocase
		$url3 = "https://crypto-loot.com/lib/miner.min.js" nocase
		$url4 = "https://camillesanz.com/lib/status.js" nocase
		$url5 = "https://www.coinblind.com/lib/coinblind_beta.js" nocase
		$url6 = "http://jquerystatistics.org/update.js" nocase
		$url7 = "http://www.etacontent.com/js/mone.min.js" nocase
		$url8 = "https://cazala.github.io/coin-hive-proxy/client.js" nocase
		$url9 = "http://eruuludam.mn/web/coinhive.min.js" nocase
		$url10 = "http://www.playerhd2.pw/js/adsensebase.js" nocase
	condition:
		$a1 or $a2 or 1 of ($url*)	
}
rule Trojan_c: apt36
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
rule fakeapps009_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81")
}
rule Ahmyth_test_a
{
	meta:
		description = "This rule detects ahmyth packaged apps"
	strings:
		$a1 = "done"
		$a2 = "collecting"
		$a3 = "cannot"
		$a5 = "inaccessible"
		$a6 = "Network"
		$a7 = "DIRR"
		$a8 = "external storage access error"
	condition:
		all of ($a*)
}
rule WhatsApp_a: Virus
{
	condition:
	   androguard.url("google.com/iidKZ.KxZ/=-Z[")
}
rule AppInstaller_a
{
    meta:
	description = "The app installs other apps or at least interested in newly installed Apps"
    condition:
	androguard.filter(/com.android.vending.INSTALL_REFERRER/) or
	androguard.permission(/INSTALL_PACKAGES/)
}
rule Keylogger_a
{
    meta:
	description = "A potential Keylogger. looking for filter cuz andoguard cannot detect the inline permission"
    condition:
	androguard.filter(/accessibilityservice.AccessibilityService/) or
	androguard.permission(/BIND_ACCESSIBILITY_SERVICE/)
}
rule DeviceAdmin_a
{
    meta:
        description = "Checks for Device Admin filters, enables the app to control the device"
    condition:
	androguard.filter(/ACTION_DEVICE_ADMIN/) or
	androguard.permission(/BIND_DEVICE_ADMIN/)
}
rule Veri5DigitalTracker_a
{
	meta:
		description = "This rule detects Veri5 Digital SDK"
	strings:
		$a = "https://sandbox.veri5digital.com/video-id-kyc/api/1.0/"
		$b = "https://prod.veri5digital.com/video-id-kyc/api/1.0/"
	condition:
		($a or $b)  and
		androguard.permission(/android.permission.INTERNET/)
}
rule riltok_koo_a
{
    strings:
        $s1 = "librealtalk-jni.so"
        $s2 = "AmericanExpress"
        $s3 = "cziugqk"
    condition:
        all of them
}
rule findSample_a: similar
{
	condition:
		1
}
rule video_player_a:fake
{ 	
	meta:
		description = "Determine if apk is a fake Video Player"
		sample = "b7d5732b1f0895724bac1fc20994341aed74e80d1f60f175196b98147ec5887c"
	condition:
		androguard.app_name("Video Player") and
		not androguard.certificate.sha1("7106c7423d7e70cd03db17c5b1cc9827")
}
rule koodous_ca: official
{
	meta:
		description = "This rule detects when application tries to gain admin rights and wants to do something with SMS"
	strings:
		$a = "android.app.action.ADD_DEVICE_ADMIN"
		$b = "android.app.extra.DEVICE_ADMIN" nocase
		$c = "/private/tuk_tuk.php"
	condition:
		($a and $b) and (androguard.permission(/RECEIVE_SMS/) or androguard.permission(/READ_SMS/) or androguard.permission(/SEND_SMS/) or $c) 
}
rule apperhand_a: trojan
{
	meta:
		description = "This rule detects the apperhand SDK aggressive adware."
	condition:
		androguard.url(/www\.apperhand\.com/) 
		and   			
		(androguard.permission(/android.permission.INTERNET/) 
		or
		androguard.permission(/android.permission.READ_HISTORY_BOOKMARKS/) 
		or
		androguard.permission(/android.WRITE_HISTORY_BOOKMARKS/) 
		or 
		androguard.permission(/android.permission.AUTHENTICATE_ACCOUNTS/)
		or
		androguard.permission(/android.permission.SET_TIME_ZONE/))
}
rule Minecraft_a
{
	meta:
		description = "A rule to detect malicious Minecraft APKS. Minecraft should not do anything with SMSes and should not need phone information such as boot completed. It should also not do https requests and access elemnts of the page."
		sample = "35bb105bd203c0677466d2e26e71a28ba106f09db3a7b995e796825f5f0e1908"
	strings:
		$js_class = /getElement(sByClassName | ByID )/
		$click = "click()"
	condition:
		androguard.app_name(/Minecraft/) and (
		$js_class or $click or
		androguard.url("https://api.onesignal.com/") or
		androguard.permission(/android.permission.READ_SMS/) or
		androguard.permission(/android.permission.SEND_SMS/) or
		androguard.permission(/android.permission.RECEIVE_SMS/) or
		androguard.permission(/android.permission.WRITE_SMS/) or
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) or
		androguard.permission(/android.permission.READ_PHONE_STATE/) or
		androguard.permission(/android.permission.USER_PRESENT/) or
		androguard.activity(/\.sms\./)
		)
}
rule koodous_da: official
{
	strings:
		$MD5 = "8037c51ababaaeb8da4d8a0b460223a2"
		$SHA1 = "b657d2817ff6d511d6c2b725c58180721d1e153c"
		$AppName = "Hediye Kutusu"
		$Developer = "Hediye Fun Corp."
	condition:
		$MD5 or $SHA1 or $AppName or $Developer
}
rule koodous_ea: official
{
	strings:
		$MD5 = "5f08fb3e2fc00391561578d0e5142ecd"
		$SHA1 = "db35baeb9fc92ea28b116ec7da02af1cd0797dcf"
		$AppName = "Viber"
		$Developer = "UMT inc."
	condition:
		$MD5 or $SHA1 or $AppName or $Developer
}
rule quickshortcuu_a
{
	meta:
		description = "rule to detect a repackage of quickshortcut using the quickshortcuu name"
		sample = "fc305e74aa702b7cae0c13369abfe51e0556198cf96522c5782e06cce9a19edf"
	strings:
		$a = "com.sika524.android.quickshortcuu"
		$b = { 63 6f 6d 2e 73 69 6b 61 35 32 34 2e 61 6e 64 72 6f 69 64 2e 71 75 69 63 6b 73 68 6f 72 74 63 75 75 }
	condition:
		($a or $b) and
		androguard.app_name("QuickShortcutMaker")
}
rule koodous_fa: official
{
    meta:
        description = "detect potential malware"
    condition:
        androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and 
        androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and 
        androguard.permission(/android.permission.RECORD_AUDIO/) and 
		androguard.permission(/android.permission.INTERNET/)
}
rule Downloader_a
{
    meta:
        description = "This rule detects the Downloader app from Koodous"
    strings: 
    $md5 = {226b9a8e0da1a93fba65247a73ae6f8504f6c65a97336c4a3a2db9fb4f1df6a6}
	$sha1 = {896bdf295a7ee8089349426b7950615f2a0d41e9}
	$package = "com.ossibussoftware.deadpixeltest"
	$method = "com/google/android/gms/ads/identifier/AdvertisingIdClient$Info;->isLimitAdTrackingEnabled()Z"
    condition:
        $md5 and $sha1 and $package and $method
}
rule tiffintomsus_a
{
	meta:
		description = "This rule detects suspicious tiffintom activity"
		sample = "6e2c3900d9775696bd401cdfb6924f66c3283cd10666cebc930a1d01f9bf9807"
	condition:
		androguard.activity(/\.tiffintom\./) or
    	androguard.activity("com.tiffintom.tiffintom.sdk.activity.PermissionsActivity") 
}
rule fake_updater_a
{
	meta:
		description = "This rule detects malicious software based on a fake google play store updater"
		sample = "1dbf4530efd1bab8e298c4553f7873372511b4159a35de446716fd9ae60b6ecb"
	strings:
		$a = "android/telephony/TelephonyManager;->getDeviceId"
		$b = "android/telephony/TelephonyManager;->getSimSerialNumber"
		$c = "android/telephony/TelephonyManager;->getLine1Number"
		$d = "android/telephony/TelephonyManager;->getSubscriberId"
		$e = "android/app/ActivityManager;->getRunningTasks"
		$f = "android/net/ConnectivityManager;->getActiveNetworkInfo"
		$g = "android/telephony/SmsManager;->sendTextMessage"
	condition:
		any of them
}
rule apkDetect_a
{
	meta:
		description = "This rule detects Ransomware"
		sample = "fdd2004bbd0f6b3742330b196c386931235249af34e13141caf0afd17d39fa09"
	strings:
		$a = "http://1downloadss0ftware.xyz/gogo/go.php?name=Pianist%20HD%20:%20Piano"
	condition:
		androguard.app_name("Pianist HD Piano") and
		androguard.certificate.sha1("34b62a18d916cb599aceedc856d597b500b698bd") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.CHANGE_NETWORK_STATE/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.INTERNET/) and 
		$a
}
rule koodous_ga: official
{
	meta:
		description = "This rule detects apks that uses permissions which it should definitely not be able to use."
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name("com.bzyg.zhongguozhexuejianshi") and
		androguard.app_name("A Brief History of Chinese Philosophy") and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.ADD_VOICEMAIL/) and
		androguard.certificate.sha1("1dab0a0d4123f6fc17b78ee327b1b219b951f546")
}
rule Igexin2252_a
{
	meta:
		description = "igexin2.2.2."
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_a = "com.igexin.sdk.PushReceiver"
		$strings_b = "2.2.5.2"
	condition:
		any of ($strings_*)
}
rule dowgin_a:adware android
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
rule leadbolt_a: advertising
{
	meta:
		description = "Leadbolt"
	condition:
		androguard.url(/http:\/\/ad.leadbolt.net/)
}

rule android_mazarBot_z_a: android
{
	meta:
	  author = "https://twitter.com/5h1vang"
	  reference_1 = "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"
	  description = "Yara detection for MazarBOT"
	  sample = "73c9bf90cb8573db9139d028fa4872e93a528284c02616457749d40878af8cf8"
	strings:
		$str_1 = "android.app.extra.ADD_EXPLANATION"
		$str_2 = "device_policy"
		$str_3 = "content://sms/"
		$str_4 = "#admin_start"
		$str_5 = "kill call"
		$str_6 = "unstop all numbers"
	condition:		
		androguard.certificate.sha1("50FD99C06C2EE360296DCDA9896AD93CAE32266B") or
		(androguard.package_name("com.mazar") and
		androguard.activity(/\.DevAdminDisabler/) and 
		androguard.receiver(/\.DevAdminReceiver/) and 
		androguard.service(/\.WorkerService/i)) or 
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		all of ($str_*)
}
rule koodous_ha: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "dp.mp3"
	condition:
		any of them
}
rule MazarBot_b
{
	meta:
		description = "This rule detects Android.MazarBot"
		sample = "16bce98604e9af106a70505fb0065babbfc27b992db0c231e691cb1c9ae6377b "
		source = "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"
	strings:
		$string_1 = "assets/armeabi/polipo.mp3"
		$string_2 = "assets/armeabi/polipo_old.mp3"
		$string_3 = "assets/armeabi/tor.mp3"
		$string_4 = "assets/armeabi/tor_old.mp3"
		$string_5 = "assets/polipo.mp3"
		$string_6 = "assets/polipo_old.mp3"
		$string_7 = "assets/tor.mp3"
		$string_8 = "assets/tor_old.mp3"
		$string_9 = "assets/x86/polipo.mp3"
		$string_10 = "assets/x86/polipo_old.mp3"
		$string_11 = "assets/x86/tor.mp3"
		$string_12 = "assets/x86/tor_old.mp3"
	condition:
		(($string_1 or $string_2) and ($string_3 or $string_4)) or 
		(($string_9 or $string_10) and ($string_11 or $string_12)) or
		(($string_5 or $string_6) and ($string_7 or $string_8)) 
}
rule test_b
{
    condition:
        androguard.target_sdk >= 23 or
		androguard.max_sdk >= 23 or
		androguard.min_sdk >= 23
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
rule BankingPhisher_a: string
{
	meta:
		description = "This rule detects APKs in BankingPhisher Malware"
		sample = "8f53d3abc301b4fbb7c83865ffda2f1152d5e347"
	strings:
		$string_1 = "installed.xml"
		$string_2 = "testgate.php"
	condition:
		$string_1 or $string_2
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
rule slempo_a: package
{
	meta:
		description = "This rule detects the slempo (slembunk) variant malwares by using package name and app name comparison"
		sample = "24c95bbafaccc6faa3813e9b7f28facba7445d64a9aa759d0a1f87aa252e8345"
	condition:
		androguard.package_name("org.slempo.service")
}
rule HummingBad_a: urls
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
rule russian_domain_a: adware
{
	strings:
		$a = "zzwx.ru"
	condition:
		$a
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
rule Mulad_a
{
	meta:
        description = "Evidences of Mulad Adware via rixallab component"
	strings:
		$1 = "Lcom/rixallab/ads/" wide ascii
   	condition:
    	$1 or androguard.service(/com\.rixallab\.ads\./)
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
rule banker_Dew18_a
{
	meta:
		description = "Detects DewExample related samples"
		md5 = "510ed33e1e6488ae21a31827faad74e6"
	strings:
		$a_1 = "com.example.dew18.myapplication.MyService"
		$a_2 = "com.ktcs.whowho"
		$a_3 = "KEY_OUTGOING_REPLACE_NUMBER"
		$a_4 = "MEDIA_SCANNER_SCAN_FILE"
	condition:
		all of ($a_*)
}
rule dexguard_new_a: obfuscator
{
  meta:
    description = "DexGuard new"
  strings:
    $Loaux   = { 07 4C 6F 2F (41|61) (55|75) (58|78) 3B 00 }  // Lo/[Aa][Uu][Xx];
    $Locon   = { 07 4C 6F 2F (43|63) (4F|6F) (4E|6E) 3B 00 }  // Lo/[Cc][Oo][Nn];
    $Lolcase = { 05 4C 6F 2F ?? 3B 00 }                       // Lo/[a-z];
    $Loucase = { 05 4C 6F 2F ?? 3B 00 }                       // Lo/[A-Z];
    $Loif    = { 06 4C 6F 2F ?? (46|66) 3B 00 }               // Lo/[iI][fF];
    $Loif1U  = { 08 4C 6F 2F ?? 24 (49|69) (46|66) 3B 00 }    // Lo/[A-Z]$[iI][fF];
    $Loif2UL = { 09 4C 6F 2F ?? ?? 24 (49|69) (46|66) 3B 00 } // Lo/[a-zA-Z][a-zA-Z]$[iI][fF];
    $Lo2c    = { 06 4C 6F 2F ?? ?? 3B 00 }                    // Lo/[a-zA-z][a-zA-z];
    $Lo2crap = { 05 4C 6F 2F ?? ?? 3B 00 }                    // Lo/crap;
    $Lo3crap = { 05 4C 6F 2F ?? ?? ?? 3B 00 }                 // Lo/crap;
    $lib_runtime = "libruntime.so"
    $dexguard    = "DexGuard" nocase
    $guardsquare = "guardsquare" nocase
  condition:
        ($lib_runtime or $dexguard or $guardsquare)
        or
        (($Loaux or $Locon))
        or
        ( ($Lolcase or $Loucase or $Lo2c or 1 of ($Loif*)) and ($Lo2crap or $Lo3crap) )
}
rule unk_packer_a_a: packer
{
  meta:
    description = "Unknown packer"
    url         = "https://github.com/rednaga/APKiD/issues/71"
    example     = "673b3ab2e06f830e7ece1e3106a6a8c5f4bacd31393998fa73f6096b89f2df47"
  strings:
    $str_0 = { 11 61 74 74 61 63 68 42 61 73 65 43 6F 6E 74 65 78 74 00 } // "attachBaseContext"
    $str_1 = { 04 2F 6C 69 62 00 } // "/lib"
    $str_2 = { 17 4C 6A 61 76 61 2F 6C 61 6E 67 2F 43 6C 61 73 73 4C 6F 61 64 65 72 3B 00 } // Ljava/lang/ClassLoader;
    $str_3 = { 77 72 69 74 65 64 44 65 78 46 69 6C 65 00 } // writedDexFile
    $attachBaseContextOpcodes = {
        6f20??00??00   // invoke-super {v3, v4}, Landroid/app/Application.attachBaseContext(Landroid/content/Context;)V
        6e10??00??00   // invoke-virtual {v3}, Ljava/lang/Object.getClass()Ljava/lang/Class;
        0c??           // move-result-object v0
        1a01??00       // const-string v1, str.MS4zNiguNyIBJCQ9HAU ; 0xdfd
        6e20??00??00   // invoke-virtual {v3, v1}, Lpykqdxlnyt/iytDlJSoOg.GaoAoxCoJpRm(Ljava/lang/String;)Ljava/lang/String;
        0c??           // move-result-object v1
        12??           // const/4 v2, 0               ; Protect.java:79
        2322??00       // new-array v2, v2, [Ljava/lang/Class; ; 0x3b8
        6e30??00????   // invoke-virtual {v0, v1, v2}, Ljava/lang/Class.getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
        0c??           // move-result-object v0
        12??           // const/4 v1, 0
        2311??00       // new-array v1, v1, [Ljava/lang/Object; ; 0x3bc
        6e30??00????   // invoke-virtual {v0, v3, v1}, Ljava/lang/reflect/Method.invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
        0e00           // return-void
        0d00           // move-exception v0
        28fe           // goto 0x00002984
    }
    $xor_key = {
       21 ??         //  array-length        v2, p1
       23 ?? 17 00   //  new-array           v1, v2, [B
       12 00         //  const/4             v0, 0
       21 ??         //  array-length        v2, p1
       35 ?? ?? 00   //  if-ge               v0, v2, :2A
       48 02 ?? 00   //  aget-byte           v2, p1, v0
       21 ?3         //  array-length        v3, p2
       94 03 ?? ??   //  rem-int             v3, v0, v3
       48 03 ?? ??   //  aget-byte           v3, p2, v3
       B7 ??         //  xor-int/2addr       v2, v3
       8D ??         //  int-to-byte         v2, v2
       4F 02 ?? ??   //  aput-byte           v2, v1, v0
       D8 00 ?? ??   //  add-int/lit8        v0, v0, 1
       28 F0         //  goto                :8
       11 01         //  return-object       v1
    }
  condition:
    $attachBaseContextOpcodes and $xor_key and 3 of ($str_*)
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
rule koodous_ia: official
{
	meta:
		description = "guardit4j.fin"
	strings:
		$a = "guardit4j.fin"
	condition:
		all of them
}
rule stealien_a: protector
{
  meta:
    description = "AppSuit"
    strings:
        $a = "stealien" nocase
    condition:
        all of them
}
rule koodous_ja: official
{
	meta:
		description = "Kiwi obfuscator"
		sample = ""
	strings:
		$key = "Kiwi__Version__Obfuscator"
		$class = "KiwiVersionEncrypter"
	condition:
		any of them
}
rule koodous_ka: official
{
	meta:
		description = "libshellx"
	strings:
		$a = "libshellx" nocase
	condition:
		$a
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
rule LokiBotMobile_a
{
	strings:
		$string1 = "android.permission.BIND_DEVICE_ADMIN"
		$string2 = "android.permission.SYSTEM_ALERT_WINDOW"
        $string3 = "and your's device will reboot and"
        $string4 = "This action will RESET ALL YOUR DATA."
        $string5 = "Please, wait"
        $string6 = "AndroidManifest.xml"
	condition:
		all of them
}
rule LokiBotMobile1_a
{
	strings:
		$string1 = "Domian1"
		$string2 = "Domian2"
		$string3 = "Domian3"		
		$string4 = "Domian4"
		$string5 = "Domian5"
		$string6 = "android.permission.BIND_DEVICE_ADMIN"
		$string7 = "android.permission.SYSTEM_ALERT_WINDOW"
		$string8 = "android.permission.SYSTEM_OVERLAY_WINDOW"
	condition:
		all of them
}
rule redalertJAR_a {
	strings:
		$string_1 = /http:\/\/\S+:7878/
		$string_2 = "twitter.com"
		$string_4 = "Enable security protection"
		$string_5 = "timeapi.org"
	condition:
		all of ($string_*)
}
rule readAlertNEW_a {
	strings:
		$string_1 = "twwitter.com"
		$string_2 = /http:\/\/\S+:7878/
		$string_4 = "utc/now?%5CD"
	condition:
		all of ($string_*)
}
rule Android_OmniRat_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects OmniRat"
		source = "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co"
	strings:
		$a = "android.engine.apk"
	condition:
		(androguard.activity(/com.app.MainActivity/i) and 
		 androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/i) and 
		 androguard.package_name(/com.app/i)) and $a
}
rule Dendroid_a: android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid RAT"
	strings:
    	$s1 = "/upload-pictures.php?"
    	$s2 = "Opened Dialog:"
    	$s3 = "com/connect/MyService"
    	$s4 = "android/os/Binder"
    	$s5 = "android/app/Service"
   	condition:
    	all of them
}
rule Dendroid_2_a: android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid evidences via Droidian service"
	strings:
    	$a = "Droidian"
    	$b = "DroidianService"
   	condition:
    	all of them
}
rule Dendroid_3_a: android
{
	meta:
	author = "https://twitter.com/jsmesa"
	reference = "https://koodous.com/"
	description = "Dendroid evidences via ServiceReceiver"
	strings:
    	$1 = "ServiceReceiver"
    	$2 = "Dendroid"
   	condition:
    	all of them
}
rule Android_Dendroid_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "19-May-2016"
		description = "This rule try to detect Dendroid"
		source = "https://blog.lookout.com/blog/2014/03/06/dendroid/"
	condition:
		androguard.service(/com.connect/i) and
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i)
}
rule Android_Triada_a: android
{
  meta:
    author = "Doopel"
    description = "This rule try to detects Android.Triada.Malware"
    sample = "4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b"
  strings:
    $string_1 = "android/system/PopReceiver"
    $string_2 = "VF*D^W@#FGF"
    $string_3 ="export LD_LIBRARY_PATH"
  condition:
      any of ($string_*) and
      androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
      androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
      androguard.permission(/android.permission.GET_TASKS/) and
		  androguard.activity("org.cocos2dx.cpp.VideoPlayer") and 
			androguard.activity("com.cy.smspay.HJActivity") and 
	    androguard.activity("com.b.ht.FJA") and 
	    androguard.activity("com.door.pay.sdk.DnPayActivity") and 
	    androguard.activity("com.alipay.android.app.sdk.WapPayActivity") and 
	    androguard.activity("com.cy.pay.TiantianSMPay")
 }
rule single_section_a
{
    condition:
        elf.number_of_sections >= 1
}
rule Anubis_b: abc
{
	meta:
		description = "Exobot"
	condition:
		androguard.receiver(/AlarmRcv/) and
		androguard.receiver(/BootRcv/)
}
rule Pakistan_a
{
 strings:
   $a1 = "com.avanza.ambitwiz" wide ascii
 condition:
   $a1
}
rule Coinhive4_a
{
 strings:
   $a1 = "CoinHiveIntentService" wide ascii
   $a2 = "com.kaching.kingforaday.service.CoinHiveIntentService" wide ascii
 condition:
   any of them
}
rule android94188_a: NetTraffic
{
	meta:
		description = "This rule detects anroid94188.com related samples"
		sample = "810ffcfb8d8373c8d6ae34917e43c83f92609d89285a924a9c6cead1b988da4c"
		detail = ""
	strings:
		$ = "/api/getAlist.jsp"
		$ = "/api/getAreaId.jsp"
		$ = "/api/getAtt.jsp"
		$ = "/api/getCfg.jsp"
		$ = "/api/getdl.jsp"
		$ = "/api/getDtk.jsp"
		$ = "/api/getDtkLib.jsp"
		$ = "/api/getExit.jsp"
		$ = "/api/getFallDown.jsp"
		$ = "/api/getFloat.jsp"
		$ = "/api/getInAppFloat.jsp"
		$ = "/api/getInAppFull.jsp"
		$ = "/api/getInAppNonFull.jsp"
		$ = "/api/getLauncher.jsp"
		$ = "/api/getNewVersion.jsp"
		$ = "/api/getNotification.jsp"
		$ = "/api/getShell.jsp"
		$ = "/api/getSht.jsp"
		$ = "/api/getSI.jsp"
		$ = "/api/getSlidingScreen.jsp"
		$ = "/api/getStartDialog.jsp"
		$ = "/api/getStartFull.jsp"
		$ = "/api/getStartNonFull.jsp"
		$ = "/api/getStartPop.jsp"
		$ = "/api/getStartWin.jsp"
		$ = "/api/sendCmdFeedback.jsp"
		$ = "/api/uploadInstallApps.jsp"
		$ = "/api/uploadSale.jsp"
		$ = "/api/uploadSaleInfo.jsp"
	condition:
		any of them or
		cuckoo.network.dns_lookup(/android258\.com/) or
		cuckoo.network.dns_lookup(/android369\.com/) or
		cuckoo.network.dns_lookup(/v4api\.android369\.com/) or
		cuckoo.network.dns_lookup(/v4api\.android258\.com/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.28/) or
		cuckoo.network.dns_lookup(/qingnian94188\.com/) or
		cuckoo.network.dns_lookup(/wangyan9488\.com/) or
		cuckoo.network.dns_lookup(/91wapgo\.com/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.29/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.97/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.96/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.252/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.95/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.251/) or
		cuckoo.network.dns_lookup(/114\.119\.9\.98/) or
		cuckoo.network.dns_lookup(/211\.154\.144\.73/) or
		cuckoo.network.dns_lookup(/211\.154\.144\.71/) or
		cuckoo.network.dns_lookup(/211\.154\.144\.230/) or
		cuckoo.network.dns_lookup(/api\.wangyan9488\.com/) or
		cuckoo.network.dns_lookup(/wd\.api\.qingnian94188\.com/) or
		cuckoo.network.dns_lookup(/api\.android94188\.com/) or
		cuckoo.network.dns_lookup(/114\.119\.6\.139/) or
		cuckoo.network.dns_lookup(/api\.pigbrowser\.com/) or
		cuckoo.network.dns_lookup(/sdkapi\.shouxiaozhu\.com/) or
		cuckoo.network.dns_lookup(/zg\.api\.feifei2015ff\.com/) or
		cuckoo.network.dns_lookup(/api\.vd\.91wapgo\.com/) or
		cuckoo.network.dns_lookup(/121\.201\.37\.104/) or
		cuckoo.network.dns_lookup(/zg\.api\.android94188\.com/) or
		cuckoo.network.dns_lookup(/103\.41\.54\.143/) or
		cuckoo.network.dns_lookup(/ad\.tcmdg\.com/) or
		cuckoo.network.dns_lookup(/test\.androidzf\.com/) or
		cuckoo.network.dns_lookup(/zy\.zfandroid\.com/) or
		cuckoo.network.dns_lookup(/zy\.ardgame18\.com/) or
		cuckoo.network.dns_lookup(/ad\.hywfs\.com/) or
		cuckoo.network.dns_lookup(/zy\.innet18\.com/) or
		cuckoo.network.dns_lookup(/45\.125\.216\.210/) or
		cuckoo.network.dns_lookup(/121\.201\.67\.140/) 
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
rule RuClicker_a
{
	strings:
		$ = "CiLscoffBa"
		$ = "FhLpinkJs"
		$ = "ZhGsharecropperFx"
	condition:
 		all of them
}
rule LeakerLocker2_a
{
	condition:
		androguard.service(/x\.u\.s/)
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
rule android_mazarbot_version_three_a
{
	meta:
		description = "Yara rule to detect MazarBOT version three"
		family = "Mazarbot"
		sample = "ac2e627f1401659d87975e9e224c868d885129b49dc34c04ff01c90ac29788ef"
		author = "Disane"
	condition:
		androguard.certificate.sha1("219d542f901d8db85c729b0f7ae32410096077cb") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/)
}
rule koodous_la: official
{
	strings:
		$a = "your files have been encrypted!"
		$b = "your Device has been locked"
		$c = "All information listed below successfully uploaded on the FBI Cyber Crime Depar"
	condition:
		$a or $b or $c or androguard.package_name("com.android.admin.huanmie") or androguard.package_name("com.android.admin.huanmie")
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
rule rest_a
{
	strings:
		$ = "cards, you can resolve the confusion within your heart. Every card has two" 
	  	$ = "sides, representing the Pros and Cons of a subject. All the answers are" 
		$ = "First of all, this is a free software, but due to the high development costs" 
	condition:
		all of them
}
rule Generic_a: Suspicious Certs
{
	meta:
		description = "Generic Rule to identify APKs with suspicious certificates"
	condition:
		androguard.certificate.sha1("BD1C65A339E6D133C3C5ADB0A42205BE90F36CCD") 
		or androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB") 
		or androguard.certificate.sha1("10763B5D0F4DD9976815C1270072510E6A453798")
		or androguard.certificate.sha1("FF3488E07D179A0E5EAD90E52D12F26E100B4CA6")
		or androguard.certificate.sha1("140FC8781942E9DFF4C0E60CD3F8DDE6565A9D76")
		or androguard.certificate.sha1("5AD2ACB089F8BE5112FF5125D94036983DE3E8D5")
		or androguard.certificate.sha1("ECE521E38C5E9CBEA53503EAEF1A6DDD204583FA")
}
rule SLockerQQ_a
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/new-wannacry-mimicking-slocker-abuses-qq-services/"
	condition:
		androguard.package_name("com.android.admin.hongyan") or
		androguard.package_name("com.android.admin.huanmie") or
		androguard.app_name("TyProxy")
}
rule koodous_ma: official
{
	meta:
		description = "This rule detects LeakerLocker signatures in http://blog.trendmicro.com/trendlabs-security-intelligence/leakerlocker-mobile-ransomware-threatens-expose-user-information/"
	condition:
		file.sha256("cb0a777e79bcef4990159e1b6577649e1fca632bfca82cb619eea0e4d7257e7b") or
		file.sha256("486f80edfb1dea13cde87827b14491e93c189c26830b5350e31b07c787b29387") or
		file.sha256("299b3a90f96b3fc1a4e3eb29be44cb325bd6750228a9342773ce973849507d12") or
		file.sha256("c9330f3f70e143418dbdf172f6c2473564707c5a34a5693951d2c5fc73838459") or
		file.sha256("d82330e1d84c2f866a0ff21093cb9669aaef2b07bf430541ab6182f98f6fdf82") or
		file.sha256("48e44bf56ce9c91d38d39978fd05b0cb0d31f4bdfe90376915f2d0ce1de59658") or
		file.sha256("14ccc15b40213a0680fc8c3a12fca4830f7930eeda95c40d1ae6098f9ac05146") or
		file.sha256("cd903fc02f88e45d01333b17ad077d9062316f289fded74b5c8c1175fdcdb9d8") or
		file.sha256("a485f69d5e8efee151bf58dbdd9200b225c1cf2ff452c830af062a73b5f3ec97") or
		file.sha256("b6bae19379225086d90023f646e990456c49c92302cdabdccbf8b43f8637083e") or
		file.sha256("4701a359647442d9b2d589cbba9ac7cf56949539410dbb4194d9980ec0d6b5d4")
}
rule koodous_na: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"	
	condition:		
		androguard.permission(/android.permission.BIND_DEVICE_ADMIN/) and
		androguard.permission(/android.permission.RECEIVE_SMS/)
}
rule NqShield_a
{
	meta:
		description = "NqShield"
    strings:
		$nqshield_1 = "NqShield"
		$nqshield_2 = "libnqshieldx86"
		$nqshield_3 = "LIB_NQ_SHIELD"
	condition:
        any of them 
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
rule YaYaMarcher2_a  {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (!) v0.3_summer17"
		date = "13 Jul 2017"
		original = "1301:Marcher2"
	condition:
		androguard.filter("MainActivity.AlarmAction") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("android.intent.action.MAIN") and 
		androguard.filter("android.intent.action.QUICKBOOT_POWERON") and 
		androguard.filter("android.provider.Telephony.SMS_RECEIVED") and 
		androguard.filter("com.KHLCert.fdservice") and 
		androguard.filter("com.KHLCert.gpservice") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.CALL_PHONE") and 
		androguard.permission("android.permission.CHANGE_NETWORK_STATE") and 
		androguard.permission("android.permission.CHANGE_WIFI_STATE") and 
		androguard.permission("android.permission.GET_TASKS") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_CONTACTS") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.RECEIVE_SMS") and 
		androguard.permission("android.permission.SEND_SMS") and 
		androguard.permission("android.permission.USES_POLICY_FORCE_LOCK") and 
		androguard.permission("android.permission.VIBRATE") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_SETTINGS") and 
		androguard.permission("android.permission.WRITE_SMS")
}
rule dropper_a
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
rule groups_a: authors2
{
	meta:
		description = "To find groups of apps with old testing certificate, signapk tool used it. Recently apps should not have this certificate"
	condition:
		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81")
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
rule spyAgent_a
{
	meta:
		description = "This rule detects arabian spyware which records call and gathers user information which is later sent to a remote c&c"
		sample = "7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb"
		reference = "https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/"
	strings:
		$phone = "0597794205"
		$caption = "New victim arrived"
		$cc = "http://ksa-sef.com/Hack%20Mobaile/ADDNewSMS.php"
		$cc_alt = "http://ksa-sef.com/Hack%20Mobaile/AddAllLogCall.php"
		$cc_alt2= "http://ksa-sef.com/Hack%20Mobaile/addScreenShot.php"
		$cc_alt3= "http://ksa-sef.com/Hack%20Mobaile/ADDSMS.php"
		$cc_alt4 = "http://ksa-sef.com/Hack%20Mobaile/ADDVCF.php"
		$cc_alt5 = "http://ksa-sef.com/Hack%20Mobaile/ADDIMSI.php"
		$cc_alt6 = "http://ksa-sef.com/Hack%20Mobaile/ADDHISTORYINTERNET.php"
		$cc_alt7 = "http://ksa-sef.com/Hack%20Mobaile/addInconingLogs.php"
	condition:
		androguard.url(/ksa-sef\.com/) or ($phone and $caption) or ($cc and $cc_alt and $cc_alt2 and $cc_alt3 and $cc_alt4 and $cc_alt5 and $cc_alt6 and $cc_alt7)
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
rule android_asacub_b
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
rule Banker_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "26d704d3a84a1186ef9c94ccc6d9fbaf, efe11f32c6b02370c7a98565cadde668"
	strings:
		$a = "http://xxxmobiletubez.com/video.php"
		$b = "http://adultix.ru/index.php"
		$c = "http://adultix.ru/forms/index.php"
	condition:
		all of them
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
rule MobileOrder_a
{
	meta:
		description = "MobileOrder trojan."
		sample = "https://analyst.koodous.com/apks/4ef62ee5732b9de3f59a3c94112b0e7c90f96763c6e4a447992c38bb94fdfcf9"
	strings:
		$key ="#a@u!t*o(n)a&v^i"
		$iv = "_a+m-a=p?a>p<s%3"
		$var = "&nmea=%.1f|%.1f&g_tp=%d"
	condition:
		all of them
}
rule tachi_a
{
	meta:
		description = "This rule detects tachi apps (not all malware)"
		sample = "10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec"
	strings:
		$a = "svcdownload"
		$xml_1 = "<config>"
		$xml_2 = "<apptitle>"
		$xml_3 = "<txinicio>"
		$xml_4 = "<txiniciotitulo>"
		$xml_5 = "<txnored>"
		$xml_6 = "<txnoredtitulo>"
		$xml_7 = "<txnoredretry>"
		$xml_8 = "<txnoredsalir>"
		$xml_9 = "<laurl>"
		$xml_10 = "<txquieresalir>"
		$xml_11 = "<txquieresalirtitulo>"
		$xml_11 = "<txquieresalirsi>"
		$xml_12 = "<txquieresalirno>"
		$xml_13 = "<txfiltro>"
		$xml_14 = "<txfiltrourl>"
		$xml_15 = "<posicion>"
	condition:
		$a and 4 of ($xml_*)
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
rule koodous_oa: official
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
rule Xynyin_certs
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
rule Xynyin_cyphered
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
rule Dendroid_b
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
rule Dendroid_2_b
{
	meta:
        description = "Dendroid evidences via Droidian service"
	strings:
    	$a = "Droidian" wide ascii
    	$b = "DroidianService" wide ascii
   	condition:
    	all of them
}
rule Dendroid_3_b
{
	meta:
        description = "Dendroid evidences via ServiceReceiver"
	strings:
    	$1 = "ServiceReceiver" wide ascii
    	$2 = "Dendroid" wide ascii
   	condition:
    	all of them
}
rule clicker_a: urls
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
rule certifigate_a: teamviewer
{
	meta:
		description = "This rule detects applications with the same serial number than TeamViewer certificate"
		sample = "db1ee3a8af6fc808aecc0fbe1a36c04c8f9a28a744dc540e21669b493375aacd" //TeamViewer official app
		source = "https://www.blackhat.com/docs/us-15/materials/us-15-Bobrov-Certifi-Gate-Front-Door-Access-To-Pwning-Millions-Of-Androids.pdf"
	strings:
		$a = {03 02 01 02 02 04 4C C0 1B 8D} 
	condition:
		$a
		and not androguard.certificate.sha1("3E22144E1BA9151C08838D4C5EFF236DB48AAA32") //Excluding TV official
}
rule gustuff_a: malware
{
    condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.filter(/android.intent.action.MAIN/) and
        androguard.filter(/android.provider.Telephony.SMS_RECEIVED/) and
        androguard.filter(/android.net.conn.CONNECTIVITY_CHANGE/) and
		androguard.filter(/android.intent.action.QUICKBOOT_POWERON/) and
		androguard.filter(/android.intent.action.BOOT_COMPLETED/)
}
rule adware_hide_ikon_a {
strings: 
$ = /Cryopiggy/
$ = /Cryopiggy/ nocase wide
condition:
1 of them
}
rule OxyLabs_a
{
	meta:
		description = "This rule detects what Norman say"
	strings: 
	$src1="oxylabs.io"
	$src2 = "us-pr.oxylabs.io"
	condition:
	$src1 or $src2
}
rule koodous_pa: official
{
	meta:
		description = "Test 2 - just yara"
	strings:
		$a =  "doubleBackToExitPressedOnce"
		$b =  "onBackPressed"
	condition:
		   $a or $b
}
	meta: 
	description = "This rule try to detect Apps with onBackPressed and      doubleBackToExitPressedOnce pernmissions "
	condition:
		androguard.permission(/onBackPressed/)
		or
		androguard.permission(/doubleBackToExitPressedOnce/)
rule koodous_qa: official
{
	meta:
		description = "This rule detects some packer"
	strings:
		$a = {45 70 6F 6E 61 57 68 69 74 65 62 6F 78}
	condition:
		$a
}
rule koodous_ra: official
{
	meta:
		description = "This rule detects some packer"
	strings:
		$a = {45 70 6F 6E 61 57 68 69 74 65 42 6F 78}
	condition:
		$a
}
rule FakeAV2_Jan2020_a
{
	meta:
		description = "This rule detects Fake Av"
	strings:
		$a1 = "whitelist" nocase
        $a2 = "blacklistpackages" nocase
        $a3 = "blacklistactivities" nocase
        $a4 = "permissions" nocase
	condition:
		all of ($a*)
}
rule FakeAV_Jan2020_a
{
	meta:
		description = "This rule detects Fake Av"
	strings:
		$a1 = "whiteList"
        $a2 = "blackListPackages"
        $a3 = "blackListActivities"
        $a4 = "permissions"
	condition:
		all of ($a*)
}
rule String_search_a
{
        strings:
                $c2_1 = /sabadell\.com/ nocase
                $c2_2 = /tsb\.uk\.co/ nocase
                $c2_3 = /mx\.bancosabadel/ nocase
                $c2_4 = /bancosabadell/ nocase
                $c2_5 = /bancsabadell/ nocase
                $c2_6 = /activobank/ nocase
                $c2_7 = /uk\.co\.tsb/ nocase
                $c2_8 = /bancosabadell\.mx/ nocase
                $c2_9 = /sabadell/ nocase
        condition:
                1 of ($c2_*)
}
rule HypervergeSDKTracker_a
{
	meta:
		description = "All Hyperverge SDK Apps"
	condition:
		androguard.activity("co.hyperverge.hypersnapsdk.activities.HVFaceActivity") or
		androguard.activity("co.hyperverge.hvinstructionmodule.activities.FaceInstructionActivity")
}
rule koodous_sa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = /org.spongycastle.crypto.generators./
	condition:
		any of them
}
rule joker_notif_a
{
    strings:
        $notif_op = 
        { 
        6e 10 ?? ?? 0a 00 
        0c 00 
        6e 10 ?? ?? 00 00 
        0c 00 
        6e 10 ?? ?? 0a 00 
        0c 01 
        54 11 ?? 00 
        6e 10 ?? ?? 0a 00 
        0c 02 
        62 03 ?? ?? 
        71 10 ?? ?? 03 00 
        0c 03 
        12 44 
        23 44 ?? ?? 
        1c 05 ?? ?? 
        12 06 
        4d 05 04 06 
        1c 05 ?? ?? 
        12 17 
        4d 05 04 07 
        1c 05 ?? ?? 12 28 4d 05 04 08 12 35 1c 09 ?? ?? 4d 09 04 05 71 54 ?? ?? 10 32 0c 00 62 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 62 02 ?? ?? 23 73 ?? ?? 1c 04 ?? ?? 4d 04 03 06 6e 30 ?? ?? 21 03 0c 01 23 72 ?? ?? 62 03 ?? ?? 4d 03 02 06 6e 30 ?? ?? 01 02 0c 00 1f 00 ?? ?? ?? ?? ?? ?? 23 82 ?? ?? 1c 03 ?? ?? 4d 03 02 06 1c 03 ?? ?? 4d 03 02 07 6e 30 ?? ?? 10 02 0c 00 12 01 23 82 ?? ?? 4d 0b 02 06 4d 0a 02 07 6e 30 ?? ?? 10 02 
        }
    condition:
        $notif_op
}
rule disruptive1_a
{
	meta:
		description = "searching for disruptive ads"
	strings:
		$a = /google-ads-admob/ nocase
	condition:
		(androguard.activity(/OnBackedPressed/i) or 	 androguard.activity(/doubleBackToExitPressedOnce/i)) and
		androguard.permission(/android.permission.INTERNET/) 
		and $a
}
rule disruptive2_a
{
	meta:
		description = "searching for disruptive ads"
	strings:
		$a= "OnBackedPressed" nocase
		$b = "doubleBackToExitPressedOnce" nocase
		$c = /google-ads-admob/ nocase
	condition:
		androguard.permission(/android.permission.INTERNET/) and
		($a or $b) and
		$c
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
rule malicious_cert_a
{
	meta:
		description = "This rule detects apps with malicious certs"
		sample = "a316a8cccbee940c3f0003344e6e29db163b1c82cd688bdc255a69300470124c"
	condition:
		androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB")
}
rule Target_Instagram_a: official
{
	strings:
		$string_target_fbmessenger = "com.instagram.android"
	condition:
	($string_target_fbmessenger)
}
rule Target_FBMessenger_a: official
{
	strings:
		$string_target_fbmessenger = "com.facebook.orca"
	condition:
	($string_target_fbmessenger)
}
rule Target_Facebook_a: official
{
	strings:
		$string_target_facebook = "com.facebook.katana"
	condition:
	($string_target_facebook)
}
rule Target_Bank_DB_a: official
{
	strings:
		$string_target_bank_db = "com.db.mm.deutschebank"
	condition:
	($string_target_bank_db)
}
rule Target_Bank_Paypal_a: official
{
	strings:
		$string_target_bank_paypal = "com.paypal.android.p2pmobile"
	condition:
	($string_target_bank_paypal)
}
rule Target_Bank_CA_a: official
{
	strings:
		$string_target_bank_ca = "fr.creditagricole.androidapp"
	condition:
	($string_target_bank_ca)
}
rule koodous_ta: official
{
	meta:
		description = "First rule used to detect certain permissions"
	condition:
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/)
}
rule Generic_b: Banker
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
rule koodous_ua: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("Koodous") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139") and
		androguard.url(/koodous\.com/)
}
rule koodous_va: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = /155552155(54|56|58|60|62|66|64|68|70|72)/
	condition:
		$a
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
rule FakeAppCampaign1_a
{
	meta:
		description = "This rule detects fake application with only the payment gateway delivering no service"
		sample = "c30d57bc5363456a9d3c61f8e2d44643c3007dcf35cb95e87ad36d9ef47258b4"
	strings:
		$url1 = /https:\/\/telehamkar.com\//
		$url2 = /weezweez.ir/
	condition:
		$url1 or $url2
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
rule koodous_wa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules 	potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "debuggerpattern__rdtsc" 
		$b = "ft_jar" 
		$c = "ft_zip"
		$d = "zip_file" 
		$e = "debuggerpattern__cpuid"
	condition:
		 $a and $b and $c and $d and $e //Yes, we use crashlytics to debug our app!
}
rule koodous_xa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
	strings:
		$a = "FIN_ GIFT"
	condition:
		$a		
}
rule Jkdkdkd_Apps_a
{
	meta:
		description = "This rule detects the Jkdkdkd application"
	strings:
		$a = "Jkdkdkd"
	condition:
		$a
}
rule koodous_ya: official
{
	meta:
		description = "bank malware related"
		sample = "none"
	strings:
		$a = "bankaccount"
		$b = "msky/*/phonecall/"
	condition:
		androguard.certificate.sha1("5312c4f491cbb55f890e8b4206c890fd48ab49c5") 
		or $a
		or $b
}
rule AnubisVariant_a: Bankbot
{
    meta:
        description = "Anubis Variant : Bankbot"
        hash = "61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81"
        in_the_wild = true
    strings:
        $str1 = "/o1o/a1.php" nocase
        $str2 = "/o1o/a3.php" nocase
        $str3 = "/o1o/a12.php" nocase
    condition:
        2 of ($str*)
        and
           (
               androguard.permission(/android.permission.RECEIVE_SMS/) or 		androguard.permission(/android.permission.READ_SMS/)
           )
}
rule Trojan_d: BankBot
{
	meta:
        description = "Trojan targeting Banks"
	condition:
		(
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			and androguard.permission(/android.permission.READ_SMS/)
			and androguard.permission(/android.permission.SEND_SMS/)
			and androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		)
}
rule mspy_b: internalstring
{
	meta:
		desc = "a$ is string we found in the sample"
		sample = "8074902e0abbfcff2f23c6f6e47384ae15bc9e1aa1cabc0cc300604cdac66879"
	strings:
		$a = "MSPY_PACKAGE_NAME"
	condition:
		$a 
}
rule BITTER_b
{
	meta:
		description = "This rule detects BITTER"
	condition:
		androguard.package_name("com.secureImages.viewer.SlideShow") or
		androguard.package_name("Secure.ImageViewer") or
		androguard.package_name("droid.pixels") or
		androguard.package_name("eu.blitz.conversations") or
		androguard.package_name("com.picture.guard.view") or
		androguard.package_name("com.android.settings") 
}
rule koodous_za: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
	strings:
		$a = "DataSync" nocase
		$b = "SlideShow" nocase
      $c = "IMEI Number"  nocase
      $d = "ImageView" nocase
	condition:
		3 of them
}
rule koodous_baa: official
{
	meta:
		description = "This is apt BITTER"
	strings:
		 $a = "MainActivity===>"
    	$b = "KeepAliveJobService"
   	 	$c = "Hi, I am main here"
    	$d = "jobscheduler"
	condition:
		all of them
}
rule EventBot_a
{
	meta:
		description = "This rule detects Trojan.AndroidOS.EventBot"
		sampleMD5 = "b0dbbf5df8b1eda3c1044ddd56ec5768"
		source = "https://www.cybereason.com/blog/eventbot-a-new-mobile-banking-trojan-is-born"
	strings:
		$string_1 = "eventBot"
		$string_2 = "onAccessibilityEvent"
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
		androguard.permission(/android.permission.READ_SMS/)
}
rule TruCallerSMSThief_a
{
	meta:
		description = "This rule detects JS based TruCaller SMS Thief"
		sample = "4b7a8be741378ff56452909890fd3b82ccbee91917770064764f9df7f5bc4783"
	strings:
		$required_1 = "startHourlyTimerForSMS"
	condition:
		($required_1) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/)
}
rule hacking_team_a: stcert
{
	meta:
		description = "com.lody.virtual.client.stub.StubActivity"
		samples = "none"
	condition:
		androguard.activity("com.lody.virtual.client.stub.StubActivity*")
}
rule zooking_a: official
{
	meta:
		description = "This rule detects Zooking theme"
		sample = "8d40ecebf2d2288ba8db4442701eb7be03c28149033742491bd5373f612474ec"
	strings:
		$a = "com.zzadsdk.sdk.activity.RewardedVideo"
		$b = "http://openbox.mobilem.360.cn/third/download?downloadUrl=http%3A%2F%2Fshouji.360tpcdn.com%2F180516%2F4e09ba8f237b7ecc9a229b05e420fd88%2Fcom.zhima.wszb_450.apk&softId=3981200&from=ivvi&pname=com.zhima.wszb"
		$c =  "http://adc.vanmatt.com/pk/u/c"
		$d = "https://www.starbucks.com.cn/menu/#lto-items" 
		$e = "http://lockscreen.zookingsoft.com:8888/LockScreen/LoadBalancing"
	condition:
		androguard.certificate.sha1("5cf396ef252bc129affdb6c6f6915461bfc36205") and
		$a and $b and $c and $d and $e
}
rule videogames_b
{
    condition:
		androguard.permission("android.permission.INTERNET")
}
rule Adware_b: SnakeRecipes
{
    meta:
        description = "Possible adware application"
        sample = "0d822b51c086b0c53abcb6504110a641aa9585caaa3287438e10bdc45fe43561"
	strings:
		$c1_1 = "matbakhomwalid2017free06" nocase
		$c1_2 = "b1a78415-d04c-4698-b69c-24c3c555649c" nocase
		$c1_3 = "EhUbWAcbLRoGAD5FHQAJ" nocase
	condition:
		1 of ($c1_*)
		and (
			androguard.filter(/PACKAGE_REPLACED/) or
			androguard.filter(/PACKAGE_ADDED/)
		)
		and androguard.filter(/ghrataneomwalide06.matbakhomwalid2017free06/)
		and (
			androguard.permission(/ACCESS_NETWORK_STATE/) or 
			androguard.permission(/RECEIVE_BOOT_COMPLETED/)
		)
}
rule users_location_a
{	
	meta:
		sample = "401193787f23126097d4b7600ce8e7d118db24023039897f4a292eab2d87a499"
	strings:
		$string1 = "android/location/Location/"
	condition:
		$string1 and (
		androguard.permission(/ACCESS_FINE_LOCATION/) or
		androguard.permission(/ACCESS_COARSE_LOCATION/)
		)
}
rule get_deviceId_a
{
	strings:
		$string2 = "getdeviceId"
		$string3 = "android/telephony/TelephonyManager"
	condition:
		$string2 and $string3
}
rule SizeLimit_a
{
	condition:
		filesize > 3MB 
}
rule koodous_caa: Adware
{
	meta:
		description = "This rule detects the com.fastfood_recipes application"
		sample = "cb9c44fd146a3f05c04d5e62abed611e01e5a431ee570fa635423689f3c98d4f"
	strings:
		$a = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"
	condition:
		androguard.package_name("com.fastfood_recipes") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.BLUETOOTH/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.certificate.sha1("f2ea77200808caaa94447b601e41b9c0bc470eb6")	and
		$a
}
rule SaveMe_a
{
	meta:
		description = "This rule is to detect the SaveMe application"
	condition:
		androguard.app_name("SaveMe") and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		androguard.permission(/android.permission.WRITE_CALL_LOG/) and //write permission also gives read permission
		androguard.permission(/android.permission.WRITE_CONTACTS/) and //write permission also gives read permission
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.url("http://xxxxmarketing.com")
}
rule koodous_daa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules 	potential"
	strings:
		$a = "com.mobidisplay.advertsv1.AdvService"
		$b = "AdvService Started"
	condition:
		androguard.package_name("com.mobidisplay.advertsv1") or
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		$a and
		$b
}
rule virus1_a
{
	meta:
		description = "This rule is made to find the same virus in different apks"
		sample = "a7e231d20c56b7b797db8300176d64a2c65e319a3c6eea36c2acf9cf13cec200"
	strings:
		$s_message_to_1 = "3D Bowling would like to send a message to 7151"
		$s_message_to_2 = "3D Bowling would like to send a message to 9151"
		$s_message_to_3 = "3D Bowling would like to send a message to 2855"
		$s_message_to_4 = "3D Bowling would like to send a message to 88088"
	condition:
		androguard.app_name("3D Bowling") or
		androguard.certificate.sha1("307ce61a54c38a7e1cf7cf111a0766e5891aca96") and
		androguard.service("nht.r.LKJService") and
		androguard.receiver("nht.r.LKJReceiver") and
		androguard.receiver("b.c.OphjReceiver") and
		androguard.activity("b.c.JkActivity") and
		androguard.activity("nht.r.LKJWebA") and
		androguard.activity("nht.r.LKJHActivity") and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.INSTALL_PACKAGES/) and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		$s_message_to_1 and
		$s_message_to_2 and
		$s_message_to_3 and
		$s_message_to_4
}
rule koodous_eaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "2a401f97cba6b6fcfdb849efff9835b613d691a7a68cf86ed2a9e6ecf733c998"
	strings:
	$a = {23 43 DC C2 32 F2 51 AE AA 00 88 88 E2 6B D1 29 63}
	condition:
		androguard.package_name("com.dotgears.flappybird") and
		androguard.app_name("Flappy Bird") or
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.CAMERA/) and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.READ_CALL_LOG/) and
		androguard.permission(/android.permission.PHONE_STATE/) and
		androguard.permission(/android.permission.READ_SMS/) and
		$a 
}
rule koodous_faa: official
{
	condition:
		(androguard.service("org.telegram.messenger.AuthenticatorService") and
		androguard.service("org.telegram.messenger.NotificationsService") and not
		androguard.certificate.sha1("9723e5838612e9c7c08ca2c6573b6026d7a51f8f") )
		or
		(androguard.service("org.thunderdog.challegram.service.NetworkListenerService") and
		androguard.service("org.thunderdog.challegram.sync.StubAuthenticatorService") and not
		androguard.certificate.sha1("66462134345a6adac3c1d5aea9cef0421b7cab68") )
}
rule potentialFakeGoogle_a
{
	meta:
		description = "Some apps seems to be signing themselves fraudulently as Google, why?"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
	androguard.certificate.subject(/O=Google Inc./) or androguard.certificate.issuer(/O=Google Inc./)
}
rule permissions_a: readclipboard
{
	meta:
		description = "New permission in Android Q, such that apps need to declare if they're doing clipboard snarfing.."
	condition:
		androguard.permission(/android\.permission\.READ_CLIPBOARD_IN_BACKGROUND/)
}
rule TwelfthMileDetect_a
{
	meta:
		description = "All apps using twelfthmile SDK (https://messai.in/) for Credit Scoring"
	strings:
		$a = "twelfthmile"
	condition:
		$a or 
		androguard.service("com.twelfthmile") or 
		androguard.receiver("com.twelfthmile")
}
rule koodous_gaa: official
{
	meta:
		description = "frida check"
		sample = ""
	strings:
	$a = { FC 6F BA A9 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 FF 0F 40 D1 FF 83 3A D1 F5 0F 40 91 B5 2A 06 91 F6 0B 40 91 }
	condition:
		all of them
}
rule accessbt_a: unknown
{
	condition:
		androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
}
rule Monokle_a: lookout
{
	meta:
		description = "Monokle Android. Malware. Trojan. RC. "
	condition:
		file.sha1("722fa5222be0686150bf7ef62097035b35babcb3") or
		file.sha1("655e2a59c80c05baabd88b417a078a1f085d2ed9") or
		file.sha1("5b9d7d9b8110b245f5d53b4aab4f23a5812c4815") or
		file.sha1("72d4863a4df5337621440222a478fbf8fa6d2c9a") or
		file.sha1("fe0d426ee22c0a18d0cdcd81d9742a426f30ebcf") or
		file.sha1("8034857623f59a3804c7170095e9e792a75c442d") or
		file.sha1("b4993b08bbb0482723502c2a52da5d0a30a00f45") or
		file.sha1("8fd1211deda8214dc7b1bb81522756aa88e6d116") or
		file.sha1("d93f45ae0967c514ec0bf5ccc4987a0bd2b219b4") or
		file.sha1("d9bfe9a0bef9c0a0dc021b33cc2d2a7899aa08a0") or
		file.sha1("5bcaecf74d242c8b1accbdf20ac91cacb6b5570a") or
		file.sha1("60d5d2336321f12041192956b3e9d27ea37e61e7") or
		file.sha1("a3af46875934a038e28cbf36153b6dd1a69d1d4b") or
		file.sha1("21e8a2aed43b66fbbeb1cf4839996e2d2dc27ed2") or
		file.sha1("f910d5a09b2f678df3f56106cef3e9c0c11ce62c") or
		file.sha1("9d7c44ef99054a208ce6e05cfd9ce4e16cf6f5fb") or
		file.sha1("e8fbf33849250900ea69e4b3cc0be96607d064ac") or
		file.sha1("501c295ec2d497ad87daa1d069885b945d372499") or
		file.sha1("5354a371c7a936daa26b2410bbf7812a31ae7842") or
		file.sha1("d13eda5c914dc5fec7984ff9a2e0987c357141d3") or
		file.sha1("9cbad8d15a6c96f8e587d4bf8d57882e57bf26d6") or
		file.sha1("b138dee2b40c8f1531098d6fb00b3d841fec5ed8") or
		file.sha1("bbbd7f1776bef967b93d7c381617310a62f5f6ff") or
		file.sha1("7a5421a20f834402e0ca318b921b7741b0493b34") or
		file.sha1("f9ab3ac4b67f512cde8dce50d2797eeddbc102f8") or
		file.sha1("f7e948a6100e11064094bf46eb21fb64b53db5d0") or
		file.sha1("f3541ce42f4197fd5363756b21c5ff74c7db295c") or
		file.sha1("0026ccb2c45f0dc67e41b736d8c0e1f0d8385146") or
		file.sha1("b1896570b50aca85af521fa1fb7ae86b8aeb26fe") or
		file.sha1("5feada28d38ee41b0b9f1a38458e838445201ef0") or
		file.sha1("025c427d354cbc0a2f473972d1b6a3a53f37017c") or
		file.sha1("3a350b419e9079c2cc6ec12f2430e4cee5446fa8") or
		file.sha1("d7db5c227ad23a43f2d3fe5e3cb7e3b31c82c86a") or
		file.sha1("6e186e713f38f3843735f576f5083f4f684cc077") or
		file.sha1("c70815dbdec80302d65d8cb46197a1d787479224") or
		file.sha1("04c8dcc62704526606d05037e1209b571e504792") or
		file.sha1("8ded74c9c7c61273adf9888506870911944ca541") or
		file.sha1("4245d4d349152e9706419f03756cc52f1570d255") or
		file.sha1("d9114cea50febed7d51e15077a1893494e52f339") or
		file.sha1("f4f47c9fec3e85657cfbde92c965913c70c93867") or
		file.sha1("b0911d5eeab68723c1d9fcdada2a64b5eace5f54") or
		file.sha1("8af9997e20949e0cc8dfcb685b5c1746921ee5d1") or
		file.sha1("1e0ac49b78cf2fa5cab093d5a56f15765bbddf31") or
		file.sha1("09b4972a6ee426b974e78ca868c1937bd3c83236") or
		file.sha1("e288de6ec6759275b1af2c2a353577cc88b8dd93") or
		file.sha1("f837a54e761edafd10e7d4872f81e5c57c0585be") or
		file.sha1("44b999f4c9284b5c34cec3ffb439cb65f0da5412") or
		file.sha1("69a86eb70ebf888fdd13c910e287b3d60393012b") or
		file.sha1("01390cd14b0f17efb90d89bdd9ff7de46e008a8f") or
		file.sha1("8e34ad5b12783b8c2c5d57ae81d8e3c4fe8bf1f4") or
		file.sha1("4f2873780794d654961644fb9c2e2750213a69f8") or
		file.sha1("346fe37f451cd61cfc922eafc113798b59c807be") or
		file.sha1("ef32335fd5457274ff65437aa1615c62c77772b4") or
		file.sha1("1bd8465f5020f75f0a84dfaf6e1e935954533368") or
		file.sha1("d618a5be838713d0a117c7db2775e7614a775924") or
		file.sha1("720b29792f80c02c42c48b7d085035cd1a28ec68") 
}
rule Android_Trojan_SuspiciousPermission_LauncherMiss_Change1_a
{
	meta:
		Updated_description = "rules checks the missing launcher"
	strings:
		$a1 = "android.permission.READ_SMS" wide
		$a2 = "android.permission.SEND_SMS" wide
		$a3 = "android.permission.RECEIVE_SMS" wide
		$a4 = "android.permission.WRITE_SMS" wide
		$a5 = "android.permission.READ_CONTACTS" wide
		$a6 = "android.permission.WRITE_CONTACTS" wide
		$b1 = "android.permission.WRITE_EXTERNAL_STORAGE" wide
		$b2 = "android.permission.READ_EXTERNAL_STORAGE" wide
		$b3 = "android.permission.RECEIVE_BOOT_COMPLETED" wide
		$b4 = "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION" wide
		$b5 = "android.permission.SYSTEM_OVERLAY_WINDOW" wide
		$permission = "android.permission." wide
		$LauncherMissing = "android.intent.category.LAUNCHER" wide
		$exclude_2 = "samsung" wide
		$exclude_3 = "mediatek" wide
		$exclude_4 = "oopo" wide
		$exclude_5 = "xiaomi" wide
		$exclude_6 = "huawei" wide
		$exclude_7 = "motorola" wide
		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}
	condition:
		#permission >= 10 and $hexstr_targetSdkVersion and not ($LauncherMissing) and not (any of ($exclude_*)) and 2 of ($a*) and 2 of ($b*)
}
rule AndHooklib_a: hooker framework
{
	meta:
		description = "AndHook FrameWork"
	strings:
		$a = "AndHook"
	condition:
		$a
}
rule libprotectClass_a: packer
{
	meta:
		description = "AndHook Class"
	strings:
		$a = "AndHook"
	condition:
		$a
}
rule certificates_a
{
	meta:
		description = "Identifies apps signed with certificates that are known to be from developers who make malicious apps"
	condition:
		androguard.certificate.sha1("2FC3665C8DAAE9A61CB7FA26FB3FEDE604DA4896") or
		androguard.certificate.sha1("3645AF60F8302526D376405C596596158379C7C2")
}
rule fakeFaceAPp_a
{
        meta:
                description="Detects fake FaceApp malware/adware"
        strings:
                $a1 = "id=ru.sotnik.metallCalck"
                $a2 = "myLogs"
        condition:
                all of ($a*)
}
rule koodous_haa: official
{
	meta:
		description = "anjianmobile detect"
	condition:
		androguard.url("api.mobileanjian.com")		
		or androguard.url("mobileanjian.com")
		or androguard.url(/mobileanjian\.com/)
}
rule c2dmSEND_a
{
	meta:
		description = "Should never be present in any apps - https://firebase.google.com/docs/reference/android/com/google/firebase/iid/FirebaseInstanceIdReceiver"
	condition:
		androguard.permission(/com\.google\.android\.c2dm\.permission\.SEND/)
}
rule android_wannahydra_a
{
	meta:
		description = "Yara detection for WannaHydra"
		sample = "78c9bfea25843a0274c38086f50e8b1c"
	condition:
	(
		(
				androguard.activity(/\.ItaActivity/) or
				androguard.activity(/\.InterSplashActivity/) or
				androguard.activity(/\.SantaSplashActivity/) or 
				androguard.activity(/\.ItaJujuActivity/) or 
				androguard.activity(/\.BBSplashActivity/) or 
				androguard.activity(/\.PhishingActivity/) or 
				androguard.activity(/\.RansoActivity/) or
				androguard.activity(/\.BBCapActivity/) or 
				androguard.activity(/\.SantaCapActivity/) or 
				androguard.activity(/\.InterCapActivity/)
		) 
		and
			(
				androguard.permission(/android.permission.SEND_SMS/) and
				androguard.permission(/android.permission.READ_CALL_LOG/) and
				androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
				androguard.permission(/android.permission.CAMERA/) and
				androguard.permission(/android.permission.RECORD_AUDIO/) and
				androguard.permission(/android.permission.READ_CONTACTS/) and
				androguard.permission(/android.permission.GET_ACCOUNTS/) and
				androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
				androguard.permission(/android.permission.INTERNET/) and
				androguard.permission(/android.permission.READ_PHONE_NUMBERS/)
			)
	) 	
}
rule Leadbolt_a: ads
{
	meta:
		description = "Detects leadbolt ad urls"
	condition:
		androguard.url(/ad.leadbolt\.net/) or
		androguard.url(/ad.leadboltapps\.net/) or
		androguard.url(/ad.leadboltmobile\.net/)
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
rule Hiv13PhishingCampaign_a
{
	meta:
		description = "This campaign shows phishing payment page and gathers users card information"
		sample = "4750fcaf255107a8ee42b6a65c3ad6c609ef55601a94f2b6697e86f31cff988c"
	strings:
		$a = /hiv13.com/
	condition:
		$a
}
rule add_device_admin_activity_a: official
{
	meta:
		description = "This rule detects apps that request add device admin activity"
	strings:
		$a = "android.app.action.ADD_DEVICE_ADMIN"
	condition:
		androguard.activity(/ACTION_ADD_DEVICE_ADMIN/i) or
		$a 
}
rule pChaosVMP_a: Packers
{
	meta:
		description = "Nagapt (chaosvmp)"
		Website = "http://www.nagain.com"
	strings:
		$a = "chaosvmp"
		$b = "ChaosvmpService"
	condition:
		any of them
}
rule pLIAPP_a: Packers
{
	meta:
		description = "LIAPP"
		Website = "https://liapp.lockincomp.com"
	strings:
		$a = "LiappClassLoader"
		$b = "LIAPPEgg"
		$c = "LIAPPClient"
	condition:
		any of them
}
rule pNqShield_a: Packers
{
	meta:
		description = "NqShield"
		Website = "http://shield.nq.com"
	strings:
		$a = "NqShield"
		$b = "libnqshieldx86"
		$c = "LIB_NQ_SHIELD"
	condition:
		any of them
}
rule pBangcleSecApk_a: Packers
{
	meta:
		description = "Bangcle (SecApk)"
		Website = "http://www.bangcle.com"
	strings:
		$a = "libsecexe.x86"
		$b = "libsecmain.x86"
		$c = "SecApk"
		$d = "bangcle_classes"		
	condition:
		any of them
}
rule pTencent_a: Packers
{
	meta:
		description = "Tencent"
		Website = ".."
	strings:
		$a = "TxAppEntry"
		$b = "StubShell"
	condition:
		all of them
}
rule pAli_a: Packers
{
	meta:
		description = "Ali"
		Website = "http://jaq.alibaba.com"
	strings:
		$a = "mobisecenhance"
		$b = "StubApplication"
	condition:
		all of them
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
rule BankBot_b
{
	strings:
		$a = "/private/tuk_tuk.php"
		$b = "/set/tsp_tsp.php"
	condition:
		$a or $b
}
rule certs_a
{
	condition:
		androguard.certificate.sha1("3F65615D7151BA782F9C0938B01F4834B8E492BC") or
		androguard.certificate.sha1("AFD2E81E03F509B7898BFC3C2C496C6B98715C58") or
		androguard.certificate.sha1("E6D2E5D8CCBB5550E666756C804CA7F19A523523") or
		androguard.certificate.sha1("7C9331A5FE26D7B2B74C4FB1ECDAF570EFBD163C")          // Ransomware Locker
}
rule Bankyara_a
{
	meta:
		description = "Regla para detectar muestra de practica4"
	strings:
		$string_1 = "185.62.188.32"
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.RECEIVE_SMS/) 
		}

rule FakePostBank_a {
meta:
descripton= "Regla para Detectar Fake Post Bank"
thread_level=3
strings:
	$a = "Lorg/slempo/service/Main;" wide ascii
	$b = "http://185.62.188.32/app/remote/" wide ascii
	$c = "&http://185.62.188.32/app/remote/forms/" wide ascii
condition:
	$a or $b or $c 
}

rule FakePostBank_b {
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
rule samplep4_a
{
	meta:
		description=”samplepract”
	string:
		$a=”org/slempo/service”
		$b=”http://185.62.188.32/app/remote”
		$c=”Landroit/telephony/SmsManager”
		$d=”intercept_sms_start”
	Condition:
		$a and ($b or $c $d )
}
rule  practica4_slempo_a
{
	meta:
		description=  "BANKED_SLEMPO"
	strings:
		$a= "slempo"
		$b= "intercept_sms_start"
		$c= "unblock_all_number"
	condition:
		$a and $b and $c
}
rule test_obfuscated_marcher_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$b_1 = "vi?rus"
		$b_2 = "a?v?g"
		$b_3 = "a?nt?i"
		$b_4 = "v?i?ru?s"
	condition:
		any of ($b_*)
}
rule YARA_Act4_DG_a
{
	meta:
		description = "Esta regla detecta Malware de Postbank FinanzAssistent"
	strings:
		$a = "#intercept_sms_start" wide ascii
		$b = "#intercept_sms_stop" wide ascii
		$c = "Lorg/slempo/service/Main" wide ascii
		$d = "Lorg/slempo/service/a/" wide ascii
		$e = "com.slempo.service.activities" wide ascii
		$f = /com.slempo.service/ nocase
	condition:
		$c and ($a or $b or $d or $e or $f)
		}
rule pokemon_a
{
	condition:
		androguard.app_name(/pokemongo/i)
}
rule adware_a {
            condition:
				androguard.filter("com.airpush.android.DeliveryReceiver") or
				androguard.filter(/smsreceiver/)
				androguard.filter()
        }
rule spydealer_a: trojan
{
	meta:
		description = "This rule detects spydealer trojan"
		report = "https://researchcenter.paloaltonetworks.com/2017/07/unit42-spydealer-android-trojan-spying-40-apps/"
		sample = "4e4a31c89613704bcace4798335e6150b7492c753c95a6683531c2cb7d78b3a2"
	condition:
		androguard.activity(/AndroidserviceActivity/i) and
		androguard.activity(/Camerapic/i) and
		androguard.receiver(/PhoneReceiver/i) and
		androguard.receiver(/NetWorkMonitor/i) and
		androguard.receiver(/TimerReceiver/i) and
		androguard.service(/AaTService/i) and
		androguard.service(/FxService/i) and
		androguard.permission("android.permission.CAMERA") and
		androguard.permission("android.permission.GET_ACCOUNTS") and
		androguard.permission("android.permission.INTERNET") and
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and
		androguard.permission("android.permission.READ_CONTACTS") 
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
rule HDVP_a: official
{
	meta:
		description = "This rule detects the HD Video Player application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name("kind.love.island") and
		androguard.app_name("HD Video Player") and
		androguard.activity(/clean.proud.utility.MainActivity/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81") and
		androguard.url(/ms.applovin.com/)
}
rule GhostCtrl_a
{
	meta:
		description = "This rule detects partially GhostCtrl campaign"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		report = "http://blog.trendmicro.com/trendlabs-security-intelligence/android-backdoor-ghostctrl-can-silently-record-your-audio-video-and-more/"
	condition:
		androguard.certificate.sha1("4BB2FAD80003219BABB5C7D30CC8C0DBE40C4D64")
}
rule HD Video Player_a: official
{
	meta:
		description = "This rule detects the HD Video Player application, used to show all Yara rules potential"
		sample = "7b289810d1a0d3f62a60c4711f28f9d72349d78f0a0e3ea3aa6234e10cf0e344"
	condition:
		androguard.package_name("kind.love.island") and
		androguard.app_name("HD Video Player") and
		androguard.activity(/clean.proud.utility.MainActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81") and
		androguard.url(/ms.applovin.com/)
}
rule koodous_iaa: official
{
	meta:
		description = "FinFisher"
	condition:
		androguard.app_name("cloud service") and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		androguard.permission(/android.permission/) and
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/)
}
rule Simplelocker_Rule_a
{
	meta:
		description = "This rule detects the Simplelocker application"
	strings:
		$text_string = "privoxy.config"
		$text_in_hex = { 70 72 69 76 6f 78 79 2e 63 6f 6e 66 69 67 }
		$text_string2 = "FILES_WAS_ENCRYPTED"
		$text_in_hex2 = { 46 49 4c 45 53 5f 57 41 53 5f 45 4e 43 52 59 50 54 45 44 }
		$text_string3 = "WakeLock"
		$text_in_hex3 = { 57 61 6b 65 4c 6f 63 6b }
		$text_string4 = "DISABLE_LOCKER"
		$text_in_hex4 = { 44 49 53 41 42 4c 45 5f 4c 4f 43 4b 45 52 }
	condition:
		androguard.package_name("org.simplelocker") and
		androguard.app_name("SimpleLocker") and
		androguard.activity(/Details_Activity/i) and
		$text_string and
		$text_in_hex and
		$text_string2 and
		$text_in_hex2 and
		$text_string3 and
		$text_in_hex3 and
		$text_string4 and
		$text_in_hex4
}
rule Packer_i360_a
{
	meta:
		description = "i360"
    strings:
		$i360_1 = "libjiagu.so"
		$i360_2 = "libjiagu_art.so"
	condition:
        any of them 
}
rule loveads_a
{
    meta:
   		description = "APK contains malware of all sorts, adware/trojan"
    strings:
        $a = "https://e.crashlytics.com/spi/v2/events"
        $b = "https://settings.crashlytics.com/spi/v2/platforms/android/apps/%s/settings"
    condition:
        $a and $b
		}
rule Packer_Qihoo_a
{
	meta:
		description = "Qihoo 360"
    strings:
		$qihoo_1 = "libprotectClass.so"
		$qihoo_2 = "monster.dex"
		$qihoo_3 = "libqupc"
		$qihoo_4 = "com.qihoo.util.StubApplication"
		$qihoo_5 = "com.qihoo.util.DefenceReport"
		$qihoo_6 = "libprotectClass"
	condition:
        any of them 
}
rule TrojanCajino_a
{
    meta:
   description = "Trojan which uses the Chinese search engine Baidu"
    strings:
        $a = "com.baidu.android.pushservice.action.MESSAGE"
        $b = "com.baidu.android.pushservice.action.RECEIVE" 
        $c = "com.baidu.android.pushservice.action.notification.CLICK"
    condition:
        $a and $b and $c
}
rule Packer_Bangcle_a
{
	meta:
		description = "Bangcle (SecApk)"
    strings:
		$bangcle_1 = "libsecmain.so"
		$bangcle_2 = "libsecexe.so"
		$bangcle_3 = "bangcleplugin"	
		$bangcle_4 = "libsecexe.x86"
		$bangcle_5 = "libsecmain.x86"
		$bangcle_6 = "SecApk"
		$bangcle_7 = "bangcle_classes"	
		$bangcle_8 = "assets/bangcleplugin"
		$bangcle_9 = "neo.proxy.DistributeReceiver"
		$bangcle_10 = "libapkprotect2.so"
		$bangcle_11 = "assets/bangcleplugin/container.dex"
		$bangcle_12 = "bangcleclasses.jar"
		$bangcle_13 = "bangcle_classes.jar"
	condition:
        any of them 
}
rule Cajino_a
{
	meta:
		Author= "Anna and Felicia"
		email = "s1958410@vuw.leidenuniv.nl"
		reference= "https://www.virustotal.com/gui/file/767ae060d756dff8dcf3e477066d240e7cd861a525b2b75cb914cdace94e76b3/"
		sample = "c1a3e1a372df344b138e2edb541fdc1d7c1842726ca85a38137ca902a0e5dc6b"
		date = "04/11/2020"
		description = "This is a basic YARA rule for CEO fraud."
	strings:
		$a = "TitaniumCore"
		$b = "Landroid/app/IntentService"
	condition:
		($a or $b) or
		androguard.package_name("com.Titanium.Gloves") or
	  	androguard.certificate.sha1("db27bc861665495329fb93df30017e24ddda8d27")
}
rule otherpacker_a
{
  meta:
    description = "AppGuard"
  strings:
    $stub = "assets/appguard/"
    $encrypted_dex = "assets/classes.sox"
  condition:
   ($stub and $encrypted_dex)
}
rule dxshield_a: otherpacker
{
  meta:
    description = "DxShield"
  strings:
    $decryptlib = "libdxbase.so"
    $res = "assets/DXINFO.XML"
  condition:
     ($decryptlib and $res)
}
rule secneo_a: otherpacker
{
  meta:
    description = "SecNeo"
  strings:
    $encryptlib1 = "libDexHelper.so"
    $encryptlib2 = "libDexHelper-x86.so"
    $encrypted_dex = "assets/classes0.jar"
  condition:
     any of ($encrypted_dex, $encryptlib2, $encryptlib1)
}
rule dexprotector_a: otherpacker
{
  meta:
    author = "Jasi2169"
    description = "DexProtector"
  strings:
    $encrptlib = "assets/dp.arm.so.dat"
    $encrptlib1 = "assets/dp.arm-v7.so.dat"
    $encrptlib2 = "assets/dp.arm-v8.so.dat"
    $encrptlib3 = "assets/dp.x86.so.dat"
    $encrptcustom = "assets/dp.mp3"
  condition:
     any of ($encrptlib, $encrptlib1, $encrptlib2, $encrptlib3) and $encrptcustom
}
rule kiro_a: otherpacker
{
  meta:
    description = "Kiro"
  strings:
    $kiro_lib = "libkiroro.so"
    $sbox = "assets/sbox"
  condition:
     $kiro_lib and $sbox
}
rule jiagu_a: otherpacker
{
  meta:
    description = "Jiagu"
  strings:
    $main_lib = "libjiagu.so"
    $art_lib = "libjiagu_art.so"
  condition:
     ($main_lib or $art_lib)
}
rule qdbh_packer_a: otherpacker
{
  meta:
    description = "'qdbh' (?)"
  strings:
    $qdbh = "assets/qdbh"
  condition:
     $qdbh
}
rule unknown_packer_lib_a: otherpacker
{
  meta:
    description = "'jpj' packer (?)"
  strings:
    $pre_jar = { 00 6F 6E 43 72 65 61 74 65 00 28 29 56 00 63 6F 6D 2F 76 }
    $jar_data = { 2E 6A 61 72 00 2F 64 61 74 61 2F 64 61 74 61 2F 00 2F }
    $post_jar = { 2E 6A 61 72 00 77 00 6A 61 76 61 2F 75 74 69 6C 2F 4D 61 70 00 67 65 74 49 6E 74 00 }
  condition:
    ($pre_jar and $jar_data and $post_jar)
}
rule unicom_loader_a: otherpacker
{
  meta:
    description = "Unicom SDK Loader"
  strings:
    $decrypt_lib = "libdecrypt.jar"
    $unicom_lib = "libunicomsdk.jar"
    $classes_jar = "classes.jar"
  condition:
     ($unicom_lib and ($decrypt_lib or $classes_jar))
}
rule app_fortify_a: otherpacker
{
  meta:
    description = "App Fortify"
  strings:
    $lib = "libNSaferOnly.so"
  condition:
     $lib
}
rule nqshield_a: otherpacker
{
  meta:
    description = "NQ Shield"
  strings:
    $lib = "libnqshield.so"
    $lib_sec1 = "nqshield"
    $lib_sec2 = "nqshell"
  condition:
     any of ($lib, $lib_sec1, $lib_sec2)
}
rule medusah_a: otherpacker
{
  meta:
    description = "Medusah"
  strings:
    $lib = "libmd.so"
  condition:
    $lib
}
rule medusah_appsolid_a: otherpacker
{
  meta:
    description = "Medusah (AppSolid)"
  strings:
    $encrypted_dex = "assets/high_resolution.png"
  condition:
     $encrypted_dex and not medusah
}
rule kony_a: otherpacker
{
  meta:
    description = "Kony"
  strings:
    $lib = "libkonyjsvm.so"
    $decrypt_keys = "assets/application.properties"
    $encrypted_js = "assets/js/startup.js"
  condition:
    $lib and $decrypt_keys and $encrypted_js
}
rule approov_a: otherpacker
{
  meta:
    description = "Aproov"
  strings:
    $lib = "libapproov.so"
    $sdk_config = "assets/cbconfig.JSON"
  condition:
     $lib and $sdk_config
}
rule koodous_jaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.url(/pstatp\.com/) or
		androguard.url(/pglstatp-toutiao\.com/) or
		androguard.url(/pangolin-sdk-toutiao\.com/) or
		androguard.provider("com.bytedance.sdk.openadsdk.*")
}
rule StartAll_a
{
	meta:
		description = "All Apps"
	strings:
		$a = "AndroidManifest.xml"
	condition:
		$a 
}
rule PornHubAPK_a
{
    meta:
        Author = "Wessel van Putten and Niels Cluistra"
        email = "s2600889@vuw.leidenuniv.nl"
        description = "A rule to detect the malicious APK in the PornHub app"
    strings:
        $a= "Vgamqwt" 
        $b= "Wunec"
        $c= "android.permission.QUICKBOOT_POWERON"
        $d= "android.permission.WRITE_EXTERNAL_STORAGE"
    condition:
        $a and $b and $c and $d
}
rule DexClassLoader_a
{
	meta:
		description = "DexClassLoader"
	strings:
		$a = "Ldalvik/system/DexClassLoader;"
	condition:
		$a 
}
rule koodous_kaa: official
{
	meta:
		description = "This rule detects Cajino applications"
		sample = "B3814CA9E42681B32DAFE4A52E5BDA7A"
	condition:
		androguard.app_name("Cajino") and
		androguard.activity(/com.baidu.android.pushservice.action.RECEIVE/) and
		androguard.activity(/com.baidu.android.pushservice.action.MESSAGE/) and
		androguard.activity(/com.baidu.android.andpushservice.action.notification.CLICK/) and
		androguard.permission(/android.permission.CALL_LOG/) and
		androguard.permission(/android.permission.UPLOAD_MESSAGE/) and
		androguard.permission(/android.permission.SEND_MESSAGE/) 
}
rule antiemulator_a
{
	meta:
		description = "Detect dumb antiemulator techniques"
	strings:
		$a = "google_sdk"
		$b = "generic"
		$c = "goldfish"
	condition:
		all of them
}
rule koodous_laa: official
{
	meta:
		description = "This rule detects potential banking trojans with the interface of Chrome"
		sample = "f46c90ffd4b15655f00a0fc5cb671cc9f55f2a21457913af940b9dd32f286307"
	condition:	
	androguard.permission(/android.permission.SYSTEM_OVERLAY_WINDOW/) and
	androguard.permission (/android.permission.DISABLE_KEYGUARD/) and
	androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/)
}
rule Cajino_b
{
	meta:
		description = "This rule tries to detects push notification malware also kwnown as Cajino"
		sample = "31801dfbd7db343b1f7de70737bdbab2c5c66463ceb84ed7eeab8872e9629199"
	condition:
		androguard.package_name("Cajino_B3814CA9E42681B32DAFE4A52E5BDA7A") or
		androguard.app_name("Cajino") or
        androguard.activity("com.package.name.sendSMS") and
		androguard.activity("com.baidu.android.pushservice.action.MESSAGE") and
		androguard.activity("com.baidu.android.pushservice.action.RECIEVE") and
		androguard.activity("com.baidu.android.pushservice.action.notification.CLICK")and
		androguard.activity("android.intent.action.VIEW") or
		androguard.permission(/RECORD_AUDIO/) and
		androguard.permission(/ACCESS_FINE_LOCATION/) 
}
rule Android_Anubis_v3_a
{
	meta:
		description = "Anubis newer version."
	condition:
		(androguard.filter(/android.intent.action.USER_PRESENT/i)
		and androguard.filter(/android.provider.Telephony.SMS_DELIVER/i)
		and androguard.filter(/android.provider.Telephony.SMS_RECEIVED/i))
}
rule downloader_a:trojan
{
	meta:
		sample = "800080b7710870e1a9af02b98ea2073827f96d3fde8ef9d0e0422f74fe7b220f"
	strings:
		$a = "Network is slow, click OK to install network acceleration tool."
		$b = "Your network is too slow"
		$c = "Awesome body. Lean and sexy."
	condition:
		all of them
}
rule Anubis_Variant_two_a: BankBot
{
  meta:
        description = "Anubis malware targeting banks variant 2"
    	sample = "f782426c32b5ce3ea9283833fda577967e808bf98970b48c7e3f74dbc001b174"
  strings:
    $c2_1 = "/o1o/a6.php" nocase
    $c2_2 = "/o1o/a4.php" nocase
    $c2_3 = "/o1o/a3.php" nocase
  condition:
    2 of ($c2_*)
    and (
      androguard.permission(/android.permission.RECEIVE_SMS/) 
      or androguard.permission(/android.permission.READ_SMS/)
      or androguard.permission(/android.permission.SEND_SMS/)
    )
}
rule MobileSpy_a: simple
{
	meta:
		description = "This rule should detect old Mobilespy from 2014"
		sample = "954ac28ac07847085e8721708e3373a62d5e9c97b19976820f2eba3161131997"
	condition:
		file.sha256("954ac28ac07847085e8721708e3373a62d5e9c97b19976820f2eba3161131997") or
	 	androguard.package_name("com.retina.smileyweb.ui") or
		androguard.certificate.sha1("ADDCAD719274B94AE233E33F5923D6B9BB78A417B34B851527A0B857A616A2E4")
}
rule koodous_maa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
	strings:
		$ = /OpenSSL 1\.0\.1[a-g]/
		$ = /OpenSSL 1\.0\.0[a-l]/
		$ = /OpenSSL 0\.9\.8[a-x]/
	condition:
		any of them
}
rule LockerIns_a{
meta:
	description="Detects Locker samples that encrypt the device files"
	author="skeptre[@]gmail.com"
	filetype="apk/classes.dex"
	date="04/28/2020"
strings:
	$a1="l956y/bVK0RXi9hvy6OVaw9XhtAhzLzXZ05Bi89gz+OdZVVKiMt3lA=="
	$a2="decryptDir"
	$a3="You've successfully unblocked your device"
condition:
	all of ($a*)
}
rule iconPackRu_a {
meta:
	description="This rule targets fake apps that are passed as icon packs"
	targetDomain="These apps communicate with the hardcoded domain spasskds.ru/update.php"
	md5="df30c7d28fbe5fc4f1e2778d104ec351"
	author="skeptre[@]gmail.com"
	filetype="apk/classes.dex"
	date="04/28/2020"
strings:
	$a1 = "aHR0cDovL3NwYXNza2RzLnJ1L3VwZGF0ZS5waHA="
	$a2 = "LmFwaw=="
	$b1 = "loadUrl"
	$b2 = "UpdateAPP"
condition:
	any of($a*) and any of($b*)
}
rule koodous_naa: official
{
	meta:
		description = "This rule detects stripe related apps"  
	condition: 
        androguard.activity("com.stripe.android.view.PaymentMethodsActivity") 
}
rule apk_inside_a
{
	strings:
		$a = /META-INF\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/
	condition:
		$a
}
rule lionmobi_a
{
	meta:
		description = "lionmobi sketchy cleaner artifact"
		sample = "25f69a80ca602e9b2e81ed1c22ab62d91706bc13144ef490550aecbd7a73383a"
	condition:
		androguard.activity(/com\.example\.lakes/)
		}
rule koodous_oaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "Virbox Protector"
	condition:
		all of them
}
rule koodous_paa: official
{
	meta: 
		description = "This rule detects AD fraud"
	condition:
		androguard.url("app/ConfServlet?conf=") or androguard.url("http://ip-api.com/json/?fields=country,countryCode")
}
rule Advertisement_a {
	meta:
		description = "Yara rule to detect adware api calls within apps"
rulePurpose = "Exersice"_a
	strings:
		$a = "ad"
		$b = "ads"	
		$c = "Advertising"
		$d = "millenialmedia"
		$e = "airpush"
		$f = "apperhand"
	condition:
		$a or 
		$b or 
		($c and $d and $e and $f) or (		
			androguard.permission(/ACCESS_NETWORK_STATE/) and
			androguard.permission(/INTERNET/) and
			androguard.permission(/WRITE_EXTERNAL_STORAGE/)) or
		androguard.certificate.sha1("b254ecc73bbc4107e7f6046f3138364fc2f94f07")
}
rule Control_a
{
	meta:
		description = "A simple rule to detect the Corona Safety Mask App"
	strings:
		$a = "com.coronasafetymask.app"
		$b = "click on this link download the app and order your own face mask" 
	condition:
	androguard.permission(/android.permission.INTERNET/) and 
	androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and 
	androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and 			
	androguard.permission(/android.permission.SEND_SMS/) and 
	$a and 
	$b
}
rule corona_pkg_a: covid19
{
	condition:
		androguard.package_name(/corona/i)
}
rule covid_pkg_a: covid19
{
	condition:
		androguard.package_name(/covid/i)
}
rule corona_app_name_a: covid19
{
	condition:
		androguard.app_name(/corona/i)
}
rule covid_app_name_a: covid19
{
	condition:
		androguard.app_name(/covid/i)
}
rule Covid_a:AdFraud
{
	meta:
		description = "This rule detects the Covid19 application with AdFraud suspicious signatures"
	condition:
		(androguard.package_name(/corona/i) or
		androguard.package_name(/covid/i) or
		androguard.app_name(/corona/i) or
		androguard.app_name(/covid/i)) and		
		((androguard.permission(/android.permission.INTERNET/) and (androguard.permission(/android.permission.ACCESS_WIFI_STATE/) or androguard.permission(/CHANGE_WIFI_STATE/))) or
		(androguard.permission(/android.permission.INTERNET/) and androguard.permission(/android.permission.BIND_NOTIFICATION_LISTENER_SERVICE/)))
}
rule koodous_qaa: official
{
	meta:
		description = "This rule detects the Covid apps which use the accessibility services"
	condition:
		(androguard.package_name(/corona/i) or
		androguard.package_name(/covid/i) or
		androguard.app_name(/corona/i) or
		androguard.app_name(/covid/i)) and
		androguard.filter("android.accessibilityservice.AccessibilityService")
}
rule collectors_a
{
	meta:
		description = "Filter for private information collecting malwares"
	condition:
		androguard.permission(/android.permission.INTERNET/)
		and androguard.permission(/android.permission.READ_SMS/)
		and androguard.permission(/android.permission.READ_PHONE_STATE/)
		and androguard.permission(/android.permission.CHANGE_NETWORK_STATE/)
		and androguard.permission(/android.permission.ACCESS_WIFI_STATE/)
		and androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		and androguard.permission(/android.permission.READ_CONTACTS/)
		and androguard.permission(/android.permission.GET_ACCOUNTS/)
		and androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/)
}
rule minsdktest_a
{
	meta:
		description = "minsdkversion test grabber"
	strings:
		$a = /minSdkVersion/i
	condition:
		$a
}
rule adecosystems_a
{
    condition:
 		cuckoo.network.http_request(/ads01\.adecosystems\.com/) or cuckoo.network.http_request(/ads02\.adecosystems\.com/) or cuckoo.network.http_request(/ads03\.adecosystems\.com/) or cuckoo.network.http_request(/ads04\.adecosystems\.com/)
}
rule otherFindSMS_a
{
    strings:
        $text_string = "sendsms"
    condition:
       ($text_string or androguard.permission(/SEND_SMS/))
	   and androguard.permission(/FLASHLIGHT/)
}
rule HackedScreen_a
{
    condition:
        androguard.activity(/.*\.HackedScreen/)
}
rule pornplayer_a
{
	meta:
		description = "Porn Player, de.smarts.hysteric"
	strings:
		$a = "WLL.RSA"
	condition:
		$a
}
rule simplelocker_b_tor_a
{
	meta:
		description = "SimpleLocker.B Tor enabled"
	strings:
		$a = "1372587162_chto-takoe-root-prava.jpg"
		$b = "libtor.so"
	condition:
		$a and $b
}
rule koodous_raa: ClickFraud AdFraud SMS Downloader_Trojan
{
	meta:
		description = "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"
		sample = "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5"
	condition:
		androguard.activity(/com\.polaris\.BatteryIndicatorPro\.BatteryInfoActivity/i) and
		androguard.permission(/android\.permission\.SEND_SMS/)
}
rule LLCdev_a: official
{
	meta:
		description = "This rule detects samples fom LLC developer"
		sample = "00d0dd7077feb4fea623bed97bb54238f2cd836314a8900f40d342ccf83f7c84"
	condition:
		androguard.certificate.sha1("D7FE504792CD5F67A7AF9F26C771F990CA0CB036")
}
rule wipelocker_a_a
{
	meta:
		description = "WipeLocker.A"
	strings:
		$a = "Elite has hacked you.Obey or be hacked"
	condition:
		$a
}

rule Feabme_a: spy
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$string_a = "Android.Hardware.Usb9"
		$string_b = "<PrivateImplementationDetails>{05ec9a1c-bc7f-4614-8c3d-8a1df63a8265}"
		$string_c = "<UrlLogin>k__BackingField"
		$string_d = "txtPassword"
		$string_e = "getFacebook"
		$hex_a = { 23 00 27 00 61 73 73 65 6D 62 6C 69 65 73 2F 54 69 6E 6B 65 72 41 63 63 6F 75 6E 74 4C 69 62 72 61 72 79 2E 64 6C 6C 0A 00 20 }
	condition:
		any of ($string_*) and all of ($hex_*)
}
rule WapCash_a: official
{
	meta:
		description = "This rule detects samples fom WapCash developer"
		sample = "00d0dd7077feb4fea623bed97bb54238f2cd836314a8900f40d342ccf83f7c84"
	condition:
		androguard.certificate.sha1("804B1FED90432E8BA852D85C7FD014851C97F9CE")
}
rule koodous_saa: official
{
	meta:
		description = "This rule detects apks fom ASSD developer"
		sample = "cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e"
	condition:
		androguard.certificate.sha1("ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A")
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
rule russian_a: fakeInst
{
	condition:
		androguard.certificate.sha1("D7FE504792CD5F67A7AF9F26C771F990CA0CB036")
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
rule fraudulent_developers_a: airpush
{
	condition:
		androguard.certificate.issuer(/tegyhman/) 
		or androguard.certificate.issuer(/tengyhman/)
		or androguard.certificate.issuer(/pitorroman/) 
		or androguard.certificate.subject(/pitorroman/)
}
rule slocker_a_a
{
	meta:
		description = "SLocker.A"
	strings:
		$a = "StartLockServiceAtBootReceiver"
		$b = "148.251.154.104"
	condition:
		$a or $b
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
rule adware_b:asd
{
	condition:
		androguard.certificate.sha1("ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A")
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
rule fakeav_a
{
	condition:
	  androguard.package_name("com.hao.sanquanweishi") or
	  androguard.certificate.sha1("1C414E5C054136863B5C460F99869B5B21D528FC")
}
rule adware_c: installer
{
	condition:
		androguard.package_name("installer.com.bithack.apparatus")
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
rule walleteros_a
{
	meta:
		description = "Detects Bitcoin wallet.dat manipulation"
	strings:
		$a = "wallet.dat"
	condition:
		$a
}
rule interesting_strings_1_a
{
meta:
 description = "Search for password string"
 author = "David Garcia"
 date = "2016-02-10"
 version = "1"
strings:
 $string_1 = { 64 72 6f 77 73 61 70 }
 $string_2 = "password"
condition:
 $string_1 or $string_2
}
rule ransomware_b
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
rule Fake_Flash_a
{
  meta:
       description = "Detects fake flash apps"
   condition:
       (androguard.package_name(/com\.adobe\.flash/i) or androguard.app_name(/Adobe Flash/i)) //and not
}
rule SMS_Fraud_a
{
	meta:
		Author = "https://www.twitter.com/SadFud75"
	condition:
		androguard.package_name("com.sms.tract") or androguard.package_name("com.system.sms.demo") or androguard.package_name(/com\.maopake/)
}
rule Fake_Hill_Climb2_a
{
  meta:
      Author = "https://twitter.com/SadFud75"
      Info = "Detection of fake hill climb racing 2 apps"
  condition:
      androguard.app_name("Hill Climb Racing 2") and not androguard.certificate.sha1("F0FDF0136D03383BA4B2BE81A14CD4B778FB1F6C")
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
rule suidext_a: official
{
	meta:
		description = "detect suid"
	strings:
		$a = {50 40 2d 40 55 53 5e 2d}
	condition:
		$a
}
rule sms_suspect_a
{
	meta:
		description = "This rule detects APKs with SMS (write & send) permissions"
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/)
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
rule bas64_a
{
  strings:
      $b64 = "base64_decode"
  condition:
      $b64    
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
rule wefleet_a
{
	strings:
		$a = "wefleet.net/smstracker/ads.php" nocase
	condition:
		$a
}
rule Banker_Acecard_a
{
  meta:
      author = "https://twitter.com/SadFud75"
      more_information = "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"
      samples_sha1 = "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 	53cca0a642d2f120dea289d4c7bd0d644a121252"
  strings:
      $str_1 = "Cardholder name"
      $str_2 = "instagram.php"
  condition:
      ((androguard.package_name("starter.fl") and androguard.service("starter.CosmetiqFlServicesCallHeadlessSmsSendService")) or androguard.package_name("cosmetiq.fl") or all of ($str_*)) and androguard.permissions_number > 19
}
rule LocationStealer_a
{
	meta:
		description = "This rule detects SMS based trojans stealing location"
		sample = "e300bf8af65a58ec7dbe0602e09b24e75c2a98414e40a4bf15ddb66e78af5008"
	strings:
		$str_1 = "vova-set"
		$str_2 = "low battery"
		$str_3 = "vova-change"
		$str_4 = "vova-reset"
	condition:
		(androguard.package_name("com.service.locationservice") and
		androguard.certificate.sha1("4D5B2813770A367C8821A7024CD6DC5319A7E1C7")) or
		(androguard.permission(/android.permission.INTERNET/) and
		 androguard.permission(/android.permission.SEND_SMS/) and
		 androguard.permission(/android.permission.READ_SMS/) and 
		 all of them )
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
rule koodous_taa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "04df74589825e8d93f44a5713769c5a732282c5af9ac699663943824903dfe2b"
	strings:
		$a = "FRENCH_CUISINE"
	condition:
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and $a
}
rule koodous_uaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "04df74589825e8d93f44a5713769c5a732282c5af9ac699663943824903dfe2b"
	strings:
		$a = "french_cuisine"
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and $a
}
rule koodous_vaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "04df74589825e8d93f44a5713769c5a732282c5af9ac699663943824903dfe2b"
	strings:
		$a = "french_cuisine"
	condition:
		androguard.permission(/android.permission.INTERNET/) and $a
}
rule koodous_waa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "04df74589825e8d93f44a5713769c5a732282c5af9ac699663943824903dfe2b"
	strings:
		$a = "ASadsdk"
	condition:
		androguard.permission(/android.permission.INTERNET/) and $a
}
rule Rule_EliteVPN_a
{
meta:
description = "This rule detects the EliteVPN application, as analyzed in exercise A"
condition:
file.sha256("3350990c4d298cdb4dc94ba886a27147e501bbf8fd504d824be53cad5cb02142") and
androguard.activity("sri.gznpahefisyqjrqahrpozs.ygsbxqfxnjrszmwy.vuqnglz") and
androguard.permission(/BROADCAST_WAP_PUSH/) and
androguard.permissions_number > 10 and
androguard.url("https://facebook.com/device?user_code=%1$s&qr=1")
}
rule SauronLockerSpecialized_a: Dordy
{
	meta:
		description = "This rule detects the SauronLocker application, please let me know any of your ideas.. Just student work :]"
		sample = "a145ca02d3d0a0846a6dde235db9520d97efa65f7215e7cc134e6fcaf7a10ca8"
	condition:
		androguard.package_name("com.ins.screensaver") and
		androguard.app_name("Clash Royale Private") and
		androguard.activity(/LockActivity/i) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.receiver("com.ins.screensaver.receivers.OnBoot") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and
		androguard.service("com.ins.screensaver.services.CheckerService") and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.WRITE_CONTACTS/) and not
		androguard.certificate.sha1("2E18D3F8726B1DE631322716518FB2AEC2EBEb9E") and
		androguard.url("timei2260.myjino.ru/gateway/") and
		androguard.url("schemas.android.com/apk/res/android/")
}
rule Clipper_a: DordyRule
{
	meta:
		description = "This rule detects the Clipper apk, plese let me know how to get it better :] Just some student work"
		sample = "86507924e47908aded888026991cd03959d1c1b171f32c8cc3ce62c4c45374ef"
	condition:
		androguard.certificate.sha1("6755834C9A93ADA415C0706A6EE036AF327CDD4D") and
		androguard.package_name("/com.lemon.metamask/") or
		androguard.app_name(/MetaMask/) and
		androguard.service("com.lemon.metamask.Util.ClipboardMonitorService") or
        androguard.service(/clipboard/) and 
		androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
		androguard.url("api.telegram.org")
}
rule own_a: test
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential This is for test features of Koodous"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
	androguard.app_name("Facebook") and
		not androguard.package_name(/com.facebook.katana/) and 
		not androguard.certificate.issuer(/O=Facebook Mobile/)
}
rule koodous_xaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "4ad3af0e45727888230eaded3d319445ad60f57102feb33f2a62ef9a5c331e7d"
	strings:
		$a = "Killing all background processes..."
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and $a
}
rule koodous_yaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "4ad3af0e45727888230eaded3d319445ad60f57102feb33f2a62ef9a5c331e7d"
	strings:
		$a = "with android:layout_height=\x22wrap_content\x22"
		$b = "Points are coincident"
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and ($a or $b)
}
rule koodous_zaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "4ad3af0e45727888230eaded3d319445ad60f57102feb33f2a62ef9a5c331e7d"
	strings:
		$a = "33d68e8b-7186-454f-8c2a-eebb526ae5e9"
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		$a
}
rule koodous_baaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "4ad3af0e45727888230eaded3d319445ad60f57102feb33f2a62ef9a5c331e7d"
	condition:
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/)
}
rule Trojan_e: BankBot
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
rule Trojan_2_b: BankBot
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
rule Trojan_3_b: BankBot
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
rule Trojan_4_b: BankBot
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
rule AVG_free_a
{
	meta:
		description = "This rule detects the AVG free version malware"
		sample = "0ed6f99dadb9df5354f219875bf268c3e1d5dbee9a4754bb1b2c7026aa37ce93"
	condition:
		androguard.package_name("com.applecakerecipes.QueenStudio") or
		androguard.app_name("AVG AntiVirus 2020 for Android Security FREE") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) or
		androguard.certificate.sha1("1e1b347f62f980e4eea6051d85c203a1eeeff1a8")
}
rule koodous_caaa: official
{
	meta:
		description = "This rule detects weird permission"
	condition:
		androguard.permission(/com.im.im.qingliao.push.permission.MESSAGE/)
}
rule koodous_daaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e85cba233a555a2ecb0956c6b6fa040ad12fd9cb496fcff3d3b3a80dfe6758dc"
	strings:
		 $a1 = "U2VuZF9HT19TTVM="
       $a2 = "QUxMU0VUVElOR1NHTw=="
       $b1 = "Send_GO_SMS"
       $b2 = "del_sws"
	condition:
		all of ($a*) or all of ($b*)
}
rule Developers_with_known_malicious_apps_a
{
	meta:
		description = "This rule lists app from developers with a history of malicious apps"
		sample = "b1"
	strings:
	condition:
		(androguard.certificate.Md5("62DCF5128907311EA3FA0BF78FB6B25E")) or
		(androguard.certificate.sha1("1CA6B5C6D289C3CCA9F9CC0E0F616FBBE4E0573B")) or
		($b and androguard.certificate.sha1("79981C39859BFAC4CDF3998E7BE26148B8D94197")) or
		($c and androguard.certificate.sha1("CA763A4F5650A5B685EF07FF31587FA090F005DD")) or
		($d and androguard.certificate.sha1("4CC79D06E0FE6B0E35E5B4C0CB4F5A61EEE4E2B8")) or
		($e and androguard.certificate.sha1("69CE857378306A329D1DCC83A118BC1711ABA352")) 
}
rule Cerberus_Permissions_a
{
	meta:
		description = "Test Rule For Cerberus Permissions"
	condition:
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
        androguard.permission(/android.permission.CALL_PHONE/) and
        androguard.permission(/android.permission.FOREGROUND_SERVICE/) and 
        androguard.permission(/android.permission.GET_ACCOUNTS/) and
        androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.READ_CONTACTS/) and
        androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and  
        androguard.permission(/android.permission.READ_PHONE_STATE/) and 
        androguard.permission(/android.permission.READ_SMS/) and 
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 
        androguard.permission(/android.permission.RECEIVE_SMS/) and 
        androguard.permission(/android.permission.RECORD_AUDIO/) and
        androguard.permission(/android.permission.REQUEST_DELETE_PACKAGES/) and 
        androguard.permission(/android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and 
    	androguard.permission(/android.permission.SEND_SMS/) and
        androguard.permission(/android.permission.USE_FULL_SCREEN_INTENT/) and
        androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)   
}
rule is_apk_a: file_type
{
  meta:
    description = "APK"
  strings:
    $zip_head = "PK"
    $manifest = "AndroidManifest.xml"
  condition:
    $zip_head at 0 and $manifest and #manifest >= 2
}
rule vkey_protector_a: obfuscator
{
  meta:
    description = "V-Key"
  strings:
    $l1_1 = "lib/arm64-v8a/libvosWrapperEx.so"
    $l1_2 = "lib/armeabi-v7a/libvosWrapperEx.so"
    $l1_3 = "lib/armeabi/libvosWrapperEx.so"
    $l1_4 = "lib/mips/libvosWrapperEx.so"
    $l1_5 = "lib/mips64/libvosWrapperEx.so"
    $l1_6 = "lib/x86/libvosWrapperEx.so"
    $l1_7 = "lib/x86_64/libvosWrapperEx.so"
    $l2_1 = "lib/arm64-v8a/libchecks.so"
    $l2_2 = "lib/armeabi-v7a/libchecks.so"
    $l2_3 = "lib/armeabi/libchecks.so"
    $l2_4 = "lib/mips/libchecks.so"
    $l2_5 = "lib/mips64/libchecks.so"
    $l2_6 = "lib/x86/libchecks.so"
    $l2_7 = "lib/x86_64/libchecks.so"
    $l3_1 = "lib/arm64-v8a/libpki.so"
    $l3_2 = "lib/armeabi-v7a/libpki.so"
    $l3_3 = "lib/armeabi/libpki.so"
    $l3_4 = "lib/mips/libpki.so"
    $l3_5 = "lib/mips64/libpki.so"
    $l3_6 = "lib/x86/libpki.so"
    $l3_7 = "lib/x86_64/libpki.so"
    $l4_1 = "lib/arm64-v8a/libloadTA.so"
    $l4_2 = "lib/armeabi-v7a/libloadTA.so"
    $l4_3 = "lib/armeabi/libloadTA.so"
    $l4_4 = "lib/mips/libloadTA.so"
    $l4_5 = "lib/mips64/libloadTA.so"
    $l4_6 = "lib/x86/libloadTA.so"
    $l4_7 = "lib/x86_64/libloadTA.so"
  condition:
    any of them and is_apk
}
rule koodous_eaaa: official
{
	meta:
		description = "This rule detects the celebhub Spyware"
		sample = "21e077ae3b20cfeb04026bc1bba540e73bf28dc62a578e45595f1c5421d29b87"
	strings:
		$a = ""
	condition:
		androguard.package_name("com.src.adulttime") and
		androguard.activity(/VideoActivity/i) and
		androguard.activity(/BaseActivity/i) and
		androguard.activity(/ContactActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECORD_AUDIO/) and
		androguard.permission(/android.permission.READ_SMS/)
}
rule Safetracker_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name(/safetracker/i)
}
rule baiduprotect_a
{
    condition:
        androguard.service("com.baidu.xshield.XshieldService") or
        androguard.service("com.baidu.xshield.XshieldJobService")
}
rule Stage1_a
{
    meta:
        description = "Op codes for loading stage 2"
    strings:
        $s1 = {70 ?? ?? ?? ?? ?? 6e ?? ?? ?? ?? ?? 0c 05 6e ?? ?? ?? ?? ?? 0c 05 6e ?? ?? ?? ?? ?? 1a ?? ?? ?? 6e ?? ?? ?? ?? ?? 6e ?? ?? ?? ?? ?? 0c 04 62 05 ?? ?? 1a}
        $s2 = {76 ?? ?? ?? ?? ?? 74 ?? ?? ?? ?? ?? 0c 12 74 ?? ?? ?? ?? ?? 0c 12 74 ?? ?? ?? ?? ?? 0c 11 1a ?? ?? ?? 74 ?? ?? ?? ?? ?? 0c 11 74 ?? ?? ?? ?? ?? 0c 03 62 11 ?? ?? 1a}
    condition:
        1 of them
}
rule coudw_a: amtrckr
{
	meta:
		family = "coudw"
	condition:
		androguard.url(/s\.cloudsota\.com/)
}
rule Play_a
{
	strings:
		$a = "setComponentEnabledSetting"
		$b = "sendTextMessage"
		$c = "sendMultipartTextMessage"
		$d = "android.app.action.DEVICE_ADMIN_ENABLED"
	condition:
		androguard.permission(/android.permission.INTERNET/) and $a and ($b or $c) and $d and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")
}
rule downloader_b: official
{
	strings:
		$a = "setComponentEnabledSetting"
		$b = "android.app.extra.DEVICE_ADMIN"
		$c = "application/vnd.android.package-archive"
		$d = "getClassLoader"
	condition:
		$a and $b and $c and $d and 
		androguard.filter("android.app.action.DEVICE_ADMIN_DISABLED") and 
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")
}
rule IDFCUPICLTracker_a
{
	meta:
		description = "All IDFC UPI SDK Apps"
	condition:
		androguard.activity("com.fss.idfc.idfcupicl")
}
rule testwahaha2_a
{
	condition:
		androguard.url("https://www.google.com.hk/")
}
rule ibers_a {
  strings:
	$string_1 = /scottishpower\.com/
	$string_2 = /avangrid\.com/
	$string_3 = /neoenergia\.com/
	$string_4 = /iberdrola/
  condition:
	any of them
}
rule string_sanitas_a
{
	meta:
		description = "Regla creada por Victor"
	strings:
		$string_1 = /sanitas\.es/
		$string_2 = /sanitas/
	condition:
		1 of ($string_*)
}
rule koodous_faaa: official
{
	meta:
		description = "possible variant of rat android"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "5af6cfde"
		$b = "Y29tLmFuZHJvaWQuc2V0dGluZ3M6c3RyaW5nL3llcw=="
	condition:
		$a or $b
}
rule koodous_gaaa: official
{
	meta:
		description = "brazilian banks"
	strings:
		$a = "itaucard"
		$b = "bradesco"
		$c = "cef"
		$d = "saldo"
		$e = "uber"
	condition:
 		$a and $b and $c and $d and $e and
		androguard.permission(/android.permission.INTERNET/) 
}
rule koodous_haaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = ".php"
	condition:
		(androguard.app_name("atualiza") or androguard.app_name("whatsapp")) and
		androguard.permission(/android.permission.INTERNET/) and
	    androguard.permission(/android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
        androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.GET_ACCOUNTS/) and
		$a		
}
rule test_crypto_clipper_a
{
	meta:
		description = "Crypto clipper"
		md5 = "24d7783aaf34884677a601d487473f88"
	strings:
		$a_2 = "ClipboardMonitorService"
		$a_3 = "ClipboardMonitor"
	condition:
		all of ($a_*)
}
rule koodous_iaaa: official
{
	meta:
		description = "fake gas lokaliza"
	strings:
		$a = "starofertashd"
		$b = "heart.php?id="
		$c = "msg=king"
	condition:
		$a or $b or $c
}
rule koodous_jaaa: official
{
	meta:
		description = "gas machineidentificator"
	strings:
		$a = "machineidentificator"
	condition:
		$a
}
rule koodous_kaaa: official
{
	meta:
		description = "whatwhere c2"
	strings:
		$a = "load.php?hwid="
	condition:
		$a
}
rule metafortress_a: obfuscator
{
  meta:
    description = "MetaFortress"
    url         = "https://www.insidesecure.com/Products/Application-Protection/Software-Protection/Code-Protection"
    sample      = "326632f52eba45609f825ab6746037f2f2b47bfe66fd1aeebd835c8031f4fdb0"
  strings:
    $a = { 00 4d65 7461 466f 7274 7265 7373 3a20 2573 0025 733a 2025 730a 00 } // MetaFortress %s.%s: %s
    $b = { 00 4d65 7461 466f 7274 7265 7373 00 } // MetaFortress
    $c = "METAFORIC"
  condition:
    ($a and $b) or $c
}
rule gemalto_protector_a: obfuscator
{
  meta:
    description = "Gemalto"
  strings:
    $l1 = "lib/arm64-v8a/libmedl.so"
    $l2 = "lib/armeabi-v7a/libmedl.so"
    $l3 = "lib/armeabi/libmedl.so"
    $l4 = "lib/mips/libmedl.so"
    $l5 = "lib/mips64/libmedl.so"
    $l6 = "lib/x86/libmedl.so"
    $l7 = "lib/x86_64/libmedl.so"
    $p1 = "Lcom/gemalto/idp/mobile/"
    $p2 = "Lcom/gemalto/medl/"
    $p3 = "Lcom/gemalto/ezio/mobile/sdk/"
  condition:
    2 of them
}
rule potential_miners_by_strings_a: miner
{
	meta:
		description = "This rule detects potential miners using only strings"
		author = "https://koodous.com/analysts/zyrik"
	strings:
        $id001 = "4Cf2TfMKhCgJ2vsM3HeBUnYe52tXrvv8X1ajjuQEMUQ8iU8kvUzCSsCEacxFhEmeb2JgPpQ5chdyw3UiTfUgapJBhBKu2R58FcyCP2RKyq"
        $id002 = "44V8ww9soyFfrivJDfcgmT2gXCFPQDyLFXyS7mEo2xTSaf7NFXAL9usGxrko3aKauBGcwZaF1duCWc2p9eDNt9H7Q8iB7gy"
        $id003 = "43QGgipcHvNLBX3nunZLwVQpF6VbobmGcQKzXzQ5xMfJgzfRBzfXcJHX1tUHcKPm9bcjubrzKqTm69JbQSL4B3f6E3mNCbU"
        $id004 = "45vSqhWgnyRKKjmiUsSpnd14UZpMoVgZWARvyepZY1fEdERMnG6gyzB8ziGB5fCg9cfoKywXdgvXVg1E9bxzPbc8CSE5huQ"
        $id005 = "46yzCCD3Mza9tRj7aqPSaxVbbePtuAeKzf8Ky2eRtcXGcEgCg1iTBio6N4sPmznfgGEUGDoBz5CLxZ2XPTyZu1yoCAG7zt6"
        $id006 = "422QQNhnhX8hmMEkF3TWePWSvKm6DiV7sS3Za2dXrynsJ1w8U6AzwjEdnewdhmP3CDaqvaS6BjEjGMK9mnumtufvLmz5HJi"
        $id007 = "42DEobaAFK67GTxX359z83ecfa2imuqgRdrdhDRo4qGnXU6WijcjmHfQoucNPxQaZjgkkG5DWkahi8QnsXKgapfhRHo4xud"
        $id008 = "43FeFPuaspxAEU7ZGEY93YBmG8nkA1x1Pgg5kTh7mYuLXCzMP3hERey6QBdKKBciuqhsakJD44bGHhJX98V3VjbZ9r1LKzx"
        $id009 = "45oLJdzMCfPFrtz46yqNNyTNKPFRvye5XB94R7sDWvZQZmoyPy6pfk9fdgJaXFs5Jp7F8R8V42UoxjXKE2Ze842Q18Lx24G"
        $id010 = "44yphkVFNewhMGi8LkgfYSSo4gbpnT7uPeGdtwvACMB6S4zY2B6D3iWY9yF7mFX6rbJ3A3fCd8cqJVbW2zYEJLLGEnYfhLy"
        $id011 = "49Bq2bFsvJFAe11SgAZQZjZRn6rE2CXHz4tkoomgx4pZhkJVSUmUHT4ixRWdGX8z2cgJeftiyTEK1U1DW7mEZS8E4dF5hkn"
        $id012 = "4ASDBruxfJ4in134jDC1ysNPjXase7sQwZZfnLCdyVggfsaJB1AxSA8jVnXwLEe1vjBhG7sfpssqMZ8YCSAkuFCELvhUaQ1"
        $id013 = "Q0105005d36e565f5487c1d950e59a04c05c4f410345d460d8bd4d59ca2428fe7b69cf6b787fa92"
        $id014 = "44ea2ae6ec816e7955d27bf6af2f7c2e6ce36c142ee34e428dbcc808af9bc078"
        $id015 = "515b125d8a9fbc944f8652841869335d21fb0a2968c3"
        $id016 = "RHDMXKDoD2aYDwX5PRM0IUfNrQMv9yCR"
        $id017 = "1eUqLvDauJzZUjLlxvEBJfaMXpcCvOum"
        $id018 = "OkcKKX6waOTc0sRFwJXdh5PFTobpRMow"
        $id019 = "6GlWvU4BbBgzJ3wzL3mkJEVazCxxIHjF"
        $id020 = "8LqXh2UY7QzxwK2PrIQLn3iwd7HfuYgt"
        $id021 = "BLAXcU2ALlc06bhhl4Dj64Wbj44hnKYO"
        $id022 = "bLXRob0Mov5Po9c0fSrXexaJkciBo5Dp"
        $id023 = "E2B9t9yVqR62YaRw4wWX3jfadGdxcRfH"
        $id024 = "esp9hnZ3rOao2IadnClF11r6PWtExGAB"
        $id025 = "f4JsDABslmUsqfqa1SqBxbdUFp9h8eAe"
        $id026 = "InSicsHzpAQpeRBTvV2bCRT3J5mK8IoH"
        $id027 = "ITERXYJEQszTERbPanh7CxXanvT64Q5C"
        $id028 = "N09gjytzJzCQzFy9MRuchpT6TzqMXjVB"
        $id029 = "nS4VZBZRmBGNvzfQN57Mu4aodai7Hh9U"
        $id030 = "o2nnEz8ECFPcZvqSInL1Z1xcbyYvpqzD"
        $id031 = "pRdnpY8EOPrnZdDDqYStGOTLNborIkCY"
        $id032 = "tx82bQv1RTVR5V0fe2hUMSkmyNw9zmlS"
        $id033 = "v2RuDMli7TYzHF7ge0lG5VLYUDp5ISM3"
        $id034 = "W9e1JbsYTHqCwImFfAEGfJJigBCWfYv2"
        $id035 = "Xo54zUaiQUexHS1nEkT6b038trLnt0vg"
        $id036 = "XxTxffZJjxU8rLviOim34l5O3MJMWmDK"
        $id037 = "uBiTW6jSZk7mqG4mJRq4TeHMYhwu96it"
        $id038 = "aePxi6MAxNjx4Zrza5XpYaETxzCiCAGD"
        $id039 = "ZjWTajjTeo0IFi1lE3ArPpJ9MCnsimm7"
        $id040 = "pfSLncN8wTEksroVnGo5qE2rlc0zPsu4"
        $id041 = "p3ghDUhs89AhpWiQqh01aBbSFO9BQfR6"
        $id042 = "qqWrKdZTVrXznFYcZ1icdXh3mjROzyhQ"
        $id043 = "ejYytKXlz2qRKYxsHp7yeqPyEF93sMOx"
        $id044 = "VOTOnyFz4gLoYQokkyZ0O2C67UgejX14"
        $id045 = "HtQkBqXwvzRHUdngvFWg1j84fQ62RnVo"
        $id046 = "cJsrc2H0m8rKjzXo4CF7cPLcg6znPogR"
        $id047 = "lRzS5W2NgHybxcbH5BHNnNat4QajQy51"
        $id048 = "9eJhVNC0dT3qgLWnnz0ojYkBJWDZONpO"
        $id049 = "JTGErE8qg0xjlgI8aJckAqX7uamxBCyb"
        $id050 = "ciIJoDEHvWDsFjUHfX7nDMuADREcBMjD"
        $id051 = "ivFo3gzNufGSFc4lAS7dbQecVnEwf2fn"
        $id052 = "nUNBYr6kljQAEVkfLgxRY2UavY6okT4y"
        $id053 = "rD0u5dQUdYEhyHzdUt4b4HFj5OnQfylx"
        $id054 = "sdibwtwKsYZue7Q7yCoKPy7ZwIeweQXw"
        $id055 = "CxHsGJiU1DItubcIa6r7T8bK27a4eUZG"
        $id056 = "NPYVnbZeXgvboqWU0pzUVasryJgShjMU"
        $id057 = "6VLUnZXGvLqDuABUvERNwKObgOPDnB2j"
        $id058 = "YQ1at78RnEjeEiIRzLGAGY9lFo4iHU8v"
        $id059 = "4O99dpG3I4wBLhRLutkoA2cIAkWxqiZl"
        $id060 = "DulPovFs1oAWloQEruJIMlBpsDooMI1f"
        $id061 = "nYt8fRXPWp92u8MHvtdNVOoyuYdfZIdd"
        $id062 = "fwW95bBFO91OKUsz1VhlMEQwxmDBz7XE"
        $id063 = "8SUFoIbdMUfwgDVAXgyyaC5R1k1B2ny1"
        $id064 = "1a0Cej64dYffEiItrLIeiq4GfpPtn0Hf"
        $id065 = "pnkGf8QJ92Z7QEhw8exumIL8HjKCBveQ"
        $id066 = "EjGZOcQjjaAU6sPmgtoUtgfxJSzAI7Id"
        $id067 = "3ARWsJFCmo3Kg13cnr4BAW3fP5uLLoMsbL"
        $id068 = "jPypuxLViIH1ZNallVeg9LqypsYK0wq9"
        $id069 = "ugrZV7MvW9J6Wfa1NgE7qwXFmTHhYorj"
        $id070 = "aX3rvYs5vmuTbT0rr83UDiUD0VolYCkZ"
        $id071 = "1DLnwEX2GUhmRA62aCMAveHPzUN9m2dd"
        $id072 = "8P3iejGFCkXynNojWYArCRBZ21J6zrDy"
        $id073 = "y7cM7qd7ZEEQ6MdkCtDdwo6EcOpe6Oyu"
        $id074 = "dsQIV8MsvvWHB1Q8Ky1faRlpU0qzYVg1"
        $id075 = "fljRO8IOscGvuIX6I2N6agxzVM9XoYXt"
        $id076 = "1a0Cej64dYffEiItrLIeiq4GfpPtn0Hf"
        $id077 = "dzZiMNu2ju00u997BHk2uk6n6GKbtuXw"
        $id078 = "OE4oIwyeXe5YImXY5lDLscoZZrhm9DDN"
        $id079 = "eKoOYNLHEMxcmFXrQnARORLeZo9SMlZR"
        $id080 = "aePxi6MAxNjx4Zrza5XpYaETxzCiCAGD"
        $id081 = "HN0DRyXrOpCbdkyWIZnC7UjMeXvFtkh0"
        $id082 = "1nK3FmVEeZ0bjc6Np1r63wkynuTP3oqU"
        $id083 = "aePxi6MAxNjx4Zrza5XpYaETxzCiCAGD"
        $id084 = "c0aYHt9KgnXUpmZkm7tGPW2rGXl2bM2d"
        $id085 = "bXjy6ex2L7E4nI7RATUXKQKlRVeY8pyw"
        $id086 = "ZPKnEehMXNylSyz6HFP7xBUlCADEIcPy"
        $id087 = "fqJfdzGDvfwbedsKSUGty3VZ9taXxMVw"
        $id088 = "PT13WGgxMmJoaEdMc3dDTDE5Mlp2TjNY"
        $id089 = "Jz0IWB14EmMzZDdMc3dDdnZ4R2tsaDI9"
        $id090 = "PEDk4i0UIq7GsUEAEwXs31dqKjDHUI3z"
        $id091 = "FYEAbFBG3xY5VUtE9GXC56v5UKt4xkoUkb"
        $id092 = "2HujvzmUo2nuRLLqhIHIV4sCEmRw9FIc"
        $id093 = "5xUKpsv5UFOcqf6dToqMDAtBYKn1WavS"
        $id094 = "9AYxnHCZ2H7MwagCSMDwLiSizaSbqhSp"
        $id095 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        $id096 = "anWcowZ0OspSk7SPFH0itFrDrNyCpVXp"
        $id097 = "cLfiFmhE82tUfGodiYgS3U1ewQpMa2nc"
        $id098 = "DUMWz54MXfCcQGUufjx7aeBlGgaurUcU"
        $id099 = "dWzYVbhggge684eSOBSvN7gEoGs9Mjc"
        $id100 = "fz0unvRkvThZ7DcPzxfMnZoTEpZJoblt"
        $id101 = "JCchrP65tMKei1yeLQGtaOdZxXtxZryy"
        $id103 = "o2iHliDUYieOuXz3wME2NjZW79a5apK5"
        $id104 = "oQtjTDL7Jzpj8yTCD8RJMN3cxLt3pXUD"
        $id105 = "QnXbx7vLFIUq9FT0kfNZSjBkUD0GCcqi"
        $id106 = "ZHg7IgsgCYIQLhWEnLVFq06yKedNkKC9"
        $id107 = "eXnvyAQwXxGV80C4fGuiRiDZiDpDaSrf"
        $id108 = "1NeoArmnGyWHKfbje9JNWqw3tquMY7jHCw"
        $id109 = "LA7Ida655adggnBNrMgKfj7ufCwUSBQwZb7"
        $js001 = "minercry.pt/processor.js"
        $js002 = "lib/crypta.js"
        $js003 = "authedmine.com/lib/authedmine.min.js"
        $js004 = "coin-hive.com/lib/coinhive.min.js"
        $js005 = "coinhive.com/media/miner.htm"
        $js006 = "coinhive.com/lib/coinhive.min.js"
        $js007 = "cryptaloot.pro/lib/crypta.js"
        $js008 = "webminerpool.com/miner.js"
        $js009 = "play.gramombird.com/app.js"
        $js010 = "CoinHive.User("
        $js011 = "CoinHive.Anonymous("
        $js012 = "CoinHive.Token("
        $js013 = "CoinHive"
        $js015 = "miner.start("
        $js016 = "coinhive_site_key"
        $js017 = "MinerPage.prototype.startStopMine("
        $js018 = "Android.onMiningStartedJS()"
        $js019 = "javascript:startminer("
        $js020 = "javascript:startMining()"
        $js021 = "javascript:stopMining()"
        $js022 = "CRLT.Anonymous("
        $js023 = "CoinImp.Anonymous("
        $js024 = "Client.Anonymous("
        $js025 = "NFMiner"
        $js026 = "deepMiner.Anonymous"
        $lib001 = "libminer.so"
        $lib002 = "libcpuminer.so"
        $lib004 = "libcpuminer-neon.so"
        $lib005 = "libneondetect.so"
        $lib006 = "libjpegso.so"
        $lib007 = "libcpuminerneonpie.so"
        $lib008 = "libcpuminerneon.so"
        $lib009 = "libcpuminerpie.so"
        $lib010 = "libcpuminerx86.so"
        $lib011 = "libMINERWRAPPER.so"
        $lib012 = "libCPUCHECKER.so"
        $lib013 = "minerd"
        $lib014 = "minerd_neon"
        $lib015 = "minerd_regular"
        $lib016 = "libgl-render.so"
        $lib017 = "libminersdk-neondetect.so"
        $lib018 = "libminersdk-x86.so"
        $lib019 = "libminersdk.so"
        $api001 = "Lcom/kaching/kingforaday/service/CoinHiveIntentService"
        $api002 = "Lcom/theah64/coinhive/CoinHive"
        $api004 = "Lcom/bing/crymore/ch/model/GlobalConfig"
        $api005 = "Ler/upgrad/jio/jioupgrader/Coinhive"
        $api006 = "Lcom/mobeleader/spsapp/Fragment_Miner"
        $api007 = "Lcom/mobeleader/spsapp/SpsApp"
        $api008 = "Lcom/mobeleader/minerlib/MinerLib"
        $api009 = "Lcom/coinhiveminer/CoinHive"
        $api011 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/CoinHive"
        $api012 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/MoneroMiner"
        $api013 = "Lclub/mymedia/mobileminer/mining/coinhive/MoneroMiner"
        $api014 = "Lclub/mymedia/mobileminer/mining/litecoin/LiteCoinMiner"
        $api015 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/CoinHive"
        $api016 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/MoneroMiner"
        $api017 = "Lclub/mymedia/mobileminer/modules/mining/Miner"
        $api018 = "Lclub/mymedia/mobileminer/modules/mining/litecoin/LiteCoinMiner"
        $api019 = "Luk/co/wardworks/pocketminer/API/LitecoinPool/LitecoinPoolModal"
        $api020 = "Lcom/wiseplay/web/resources/CoinhiveBlock"
        $api021 = "Lcoinminerandroid/coinminer/cma/coinminerandroid"
        $api023 = "Lcom/minergate/miner/Miner"
        $api024 = "Lcom/minergate/miner/services/MinerService"
        $api025 = "startMiner"
	condition:
		androguard.permission(/android.permission.INTERNET/) and 
		((any of ($id*)) or
        (any of ($js*)) or 
        (any of ($lib*)) or
        (any of ($api*)))
}
rule anubis_downloader_a
{
	meta:
		description = "Anubis downloader"
		sha256 = "bc87c9fffcdac4eea1b84c62842ce1138fd90ed6"
	strings:
		$a_1 = "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"
		$a_2 = "urlAdminPanel"
		$a_3 = "kill"
		$a_4 = "idbot"
		$a_5 = "CheckCommand"
	condition:
		all of ($a_*)
}
rule redalert2_a
{
	meta:
		description = "RedAlert2.0"
		family = "Red Alert"
	condition:
		(androguard.url(/:7878/) or androguard.url(/:6280/)) or
		(androguard.service("westr.USSDService") and androguard.service("westr.service_rvetdi5xh.MessageBltService_df3jhtrgft43") and  androguard.service("westr.service_rvetdi5xh.WldService_dfgvgfd") and
		androguard.service("westr.service_rvetdi5xh.McdxService_efv3web")) or androguard.url("https://ttwitter.com/")
}
rule miners_regex_a: miner
{
	meta:
		description = "This rule detects miners application by a regex"
		author = "https://koodous.com/analysts/zyrik"
	strings:
		$regex001 = /(stratum\+tcp\:\/\/)?(([a-z0-9]*)\.)?(marketgid|(crypt(o|a)-?(loot|miningfarm|noter|\.csgocpu))|traviilo|butcalve|clgserv|50million|freshrefresher|(hide\.ovh)|jurtym?|pzoifaum|besti|mepirtedic|(gustaver\.ddns)|(jq(r?cdn|assets|errycdn|www))|adless|myeffect|nexttime|etzbnfuigipwvs|(worker\.salon)|cfcnet|bowithow|aalbbh84|ctlrnwbv|altavista|berateveng|jscdndel|mhiobjnirs|tidafors|((web)?(miner?)?(\.)?(sushi|litecoin|multi|webminer|ent|nimiq|space|graft|beep)?pool(er|s)?(\.hws|\.etn)?)|(never\.ovh)|chainblock|((coin-?(hive|have)-?)(s|r|rs|proxy|manager)?)|ethtrader|(open-?hive-?server(-?[0-9]{1,})?)|appelamule|scaleway|ppoi|(abc\.pema)|biberukalap|projectpoi|((jse?|bit|groestl|lite|cloud|plex|best)?coin(huntr|erra|nebula|lab|imp|pirate|signals|-?services?|pot|rail|-?cube|miningonline|blind)?)|(host\.d\-ns)|vidto|(eth-?pocket)|adzjzewsma|andlache|aymcsx|renhertfo|anyfiles|1q2w3|buyguard|kanke365|cloudflane|(mfio\.cf)|mine.torrent|(flare-?analytics)|monerise|terethat|hegrinhar|cnhv|encoding|megabanners|sparnove|(([a-z]{2,}cdn[0-9]{1,}|m(i|o)nero-?proxy-?[0-9]{2,})\.now)|bewaslac|papoto|((video\.)?(streaming\.)?estream)|willacrit|witthethim|nathetsof|ininmacerad|streambeam|kedtise|jsccnn|bhzejltg|depttake|adplusplus|hemnes|datasecu|netflare|flophous|noblock|ffinwwfpqi|baiduccdn1|reservedoffers|moneone|bablace|(oei1\.gq)|(wordc\.ga)|(mwor\.gq)|(aeros[0-9]{2,})|((support\.)?2giga\.(download|link))|([a-z]{2,}cdn[0-9]{1,}\.herokuapp)|rintindown|ermaseuc|wasm24|gridiogrid|cpufan|electroneum|verresof|jquery-cdn|evengparme|kdmkauchahynhrs|akgpr|(stratum\.bitcoin)|bjorksta|cfcdist|freecontent|hatcalter|sparechange|inwemo|xvideosharingeucsoft|uoldid|((crypto-?)?(wp-?)?(jscoin-?)?(light|ad-?|(authed)?(web)?|rex|app|support|(n|a)f|(m(o|i))?(n|h)(ero|key)|z|bro(wser)?|eth\.)?-?(miner?o?s?|xmr)(cripts|\.nablabee|\.nahnoji|pool|\.mining|\.nanopool|\.mobeleader|\.pr0gramm?|mytraffic|\.cryptobara|\.torrent|\.terorie|ad|-?(deu-)?[0-9]{1,2})?|\.beeppool)|((web)?-?(xmr)?-?(swift)?-?(coin)?-?(not)?-?mining(online)?)|blockchained|ledinund)\.[a-z]*/
	condition:
		androguard.permission(/android.permission.INTERNET/) and $regex001
}
rule banker_R_a: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "icici"
		$c = "setComponentEnabledSetting"
		$d = "android.app.action.ADD_DEVICE_ADMIN"
	condition:
		$a and $c and $d
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
rule adware_d {
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
rule fakeInstaller_b {
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
rule YaYaCharger_a: rule0 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "03 Jan 2018"
		url = "https://koodous.com/apks?search=efb1a6c795b81d31a15e1d49790d59ff3e474c430956340ae447364568033c03%20OR%2058eb6c368e129b17559bdeacb3aed4d9a5d3596f774cf5ed3fdcf51775232ba0%20OR%20761c805132d2080ce6d68d117bb25a297570dbf9a6cb510fcd68bf99de8e3a39"
	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		androguard.filter("android.intent.action.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE") and 
		androguard.filter("android.intent.action.BOOT_COMPLETED") and 
		androguard.filter("com.android.vending.INSTALL_REFERRER") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.CAMERA") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.READ_SMS") and 
		androguard.permission("android.permission.RECEIVE_BOOT_COMPLETED") and 
		androguard.permission("android.permission.SYSTEM_ALERT_WINDOW") and 
		androguard.permission("android.permission.WAKE_LOCK")
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
rule vpn_a
{
	strings:
		$a = "android.permission.BIND_VPN_SERVICE"
	condition:
		$a 
}
rule apkfiles_a: official
{
	meta:
		description = "Accede a un repositorio de apks"
	condition:
		androguard.url(/www\.apkfiles\.com/)
}

rule sorter_janus_a
{
	strings:
		$a = {64 65 78 0A 30}
	condition: 
		$a		
}
rule miner_suspicious_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "22581e7e76a09d404d093ab755888743b4c908518c47af66225e2da991d112f0"
	strings:
		$a_1 = "miner.start()"
		$b_2 = "libcpuminer.so"
		$b_3 = "libcpuminerpie.so"
	condition:
		$a_1 or any of ($b_*)
}
rule bankingsha_a: versi0ne
{
	meta:
		description = "This rule detects Bankers that embed the sha of the name of the targets apps"
		sample = "89f537cb4495a50b082758b34e54bd1024463176d7d2f4a445cf859f5a33e38f"
	strings:
		$sha0 = /\*6923da13f02ffae80c6f70832f2259070e74e6fa\*/
		$sha1 = /\*eee004f5b9c0be27359f50434cf3c2286c55acb6\*/
		$sha2 = /\*afbd5d3030052e8328280cf64d8c4bf51618e834\*/
		$sha3 = /\*afbd5d3030052e8328280cf64d8c4bf51618e834\*/
		$sha4 = /\*55a32856f20c9308f3356bed69824c637573470e\*/
		$sha5 = /\*9b21860b33b584b1989c8a66a8b401399f3872fc\*/
		$sha6 = /\*108adc236d6d0d0b9e258034cb8521dbb6a3f49d\*/
		$sha7 = /\*31f6405d71e4981a3f481e272b2fb0d129afab74\*/
		$sha8 = /\*080ee48abd4d9465810b4202a2db7a83c58c9a19\*/
		$sha9 = /\*0cd98c682f4b747950ed2c99fce21d9615f5faff\*/
		$sha10 = /\*fba00c82addfc985f644bffc47e5cc91f848fe5a\*/
		$sha11 = /\*216cc127f3725aeca4fec4d6b949c0599943b1e8\*/
		$sha12 = /\*e422fee08d5ef5c3821918a8a19983b697f3dd7b\*/
		$sha13 = /\*8711726fbc188f32f4631cf6f9138321a5b3aa26\*/
		$sha14 = /\*bbd23e2a2efaec9bb3c94188f96c98fc3664737a\*/
		$sha15 = /\*a06e4e77b4ca42df6c40c5afea695e9547646382\*/
		$sha16 = /\*c2e9c76df4c8870ebb255e3678127ec096fbe062\*/
		$sha17 = /\*cf0a862bd64494dc17f44032c380cddf8d2460af\*/
		$sha18 = /\*7e74dd5494eda5018a35b9475b1de7e4e0a6f4f7\*/
		$sha19 = /\*49f0bf429ee56881914e68eebe0762c86e41eb94\*/
		$sha20 = /\*692c077d657d46d1610290f0741a1a4d56c894ac\*/
		$sha21 = /\*64d8de190db52183bb24bb126f54198219935ef4\*/
		$sha22 = /\*42824e8fc87d8a2db2dc6d558a68477a9a6b689f\*/
		$sha23 = /\*d746cab7a65a95d29129e30df0fb3b5a041af8ec\*/
		$sha24 = /\*c772315587ee785145bc89c18b2a9e6f5104adbc\*/
		$sha25 = /\*c9983fb804f335ab26560d12d63ccb76f2ac6ef2\*/
		$sha26 = /\*863deb33345866899c1753a122cf589700b42a89\*/
		$sha27 = /\*96ddcfe2372034c47c23fda50192b49defa620b8\*/
		$sha28 = /\*133a2be3a669067c29050134460eca4a2c5ce527\*/
		$sha29 = /\*7770044bfe02ea92a6408b5dfba0aed9b2be7307\*/
		$sha30 = /\*9a565bd6f8ee5d043aa387583873d3371098e85f\*/
		$sha31 = /\*ef21dade0db65fa83edf31c4ca5ce892040c0c5b\*/
		$sha32 = /\*bdee232556f59ddc2177040162711a31605f25f7\*/
		$sha33 = /\*1c5acb8a30e3026da47aaee1510fafe1d379efdf\*/
		$sha34 = /\*562994ca64167e07817199b2c5f308db699b0d03\*/
		$sha35 = /\*5fa6f3e91ce437230a34bcca56f5e6d7d11ee06d\*/
		$sha36 = /\*ee9792ee5ed4de0d6a1ad44c65525aa7818e989f\*/
		$sha37 = /\*03d7999570c558cfcedee1c683ac63ecabbb39eb\*/
		$sha38 = /\*b1e6c9899dc77069aabfd8a1154c471fe0037b67\*/
		$sha39 = /\*37b556e482ded4ca459d58093b9fed688efc0eff\*/
		$sha40 = /\*a57104e5fce59bc45fb3835265c98328a491c077\*/
		$sha41 = /\*e7745b64f8ef2106b01fc0a05ab252a2eb23f688\*/
		$sha42 = /\*9821fe9c0b6a16317329672489b503bc548fcaf9\*/
		$sha43 = /\*18ff8391a04b1878cb88104d13761504455a18cd\*/
		$sha44 = /\*1e488fc038e98b2ab2e609983877ce6354120e4d\*/
		$sha45 = /\*a33e1e3f8decef7752b0f70526282d566cf5d83f\*/
		$sha46 = /\*67b0548291ee4fbec6d9e6694784e85ec79f7a9a\*/
		$sha47 = /\*fca863c4c30b3498386a73962a5f1b1ea86779c8\*/
		$sha48 = /\*1eb85abcf24ba0fb80e6e04d30f3b41da1f87d31\*/
		$sha49 = /\*a5b5c44fceef5ecd4e46a783cc7f54ba78e0e3ac\*/
		$sha50 = /\*3b315d6468d0907abb2cb8a4111ec64d5dfd073d\*/
		$sha51 = /\*d5c79e7bc7263c2fa06e0d68919f7ff608cc7b03\*/
		$sha52 = /\*dcedfe360ee2e0c8c274bfcf78dba28d53787ce1\*/
		$sha53 = /\*77f10a83501449d025a6d24d51ab5304b4c8548f\*/
		$sha54 = /\*1b4b6620f3f53f98d7cc8b80627989df36bc1d86\*/
		$sha55 = /\*ae590c0571afa9bb3dc99e774017ef6bd61452cb\*/
		$sha56 = /\*b337169cfb4de095c1d368776dc110d991440691\*/
		$sha57 = /\*ed3b23140e2a559b7d9e982c9de08dbf653c0910\*/
		$sha58 = /\*e4cc9dc914668ac18aa568e1c08129a28381b9df\*/
		$sha59 = /\*ed98c14b028ab1e35b6fbc5555b25c3e597998d5\*/
		$sha60 = /\*d11f06f0a5709f2272aeaec3de189427d9da3686\*/
		$sha61 = /\*b78dd8f0977eaf3eec4de326e2ba089d59444fa9\*/
		$sha62 = /\*58986e9915af4dfdd8e7f9228c95457fb03b528b\*/
		$sha63 = /\*9165a9c67a4b509b07fe8b155090b7b012fa471b\*/
		$sha64 = /\*7d1c35e47456a08bd8246bcec1654ceec4499eb4\*/
		$sha65 = /\*cb6b8e19979f6c79360021a5b93c3665b9bbae6a\*/
		$sha66 = /\*800603322b1825e416f5bfc4125b26b075a57603\*/
		$sha67 = /\*d7ef30fa72c8a7c4fa83f69d87e829f411c9eb8f\*/
		$sha68 = /\*820ab154fbb064a54ffedbf5fc29791c40135695\*/
		$sha69 = /\*41848c7c6c1eeaaa13f5ea3dec46e199929289cf\*/
		$sha70 = /\*3fc861fb56860106a2b295244ac06e9fbec51d99\*/
		$sha71 = /\*ffe079dc7f3954f1ee5cb938b5195b9713b9fccc\*/
		$sha72 = /\*c997beaef53027222e1be15f21657ae1d3a67dc5\*/
		$sha73 = /\*b90935e573dcfcfe7c677622a515894b66ed39e2\*/
		$sha74 = /\*6ff0c1dc9663b75532417cea43ef385bb1476f0c\*/
		$sha75 = /\*fc4b663c09eae08d8778299905f617087d00cc65\*/
		$sha76 = /\*2ff85b56d837f61d68683447e35c4ea8653a58c2\*/
		$sha77 = /\*cc78fa62e111139d017998b488ea0a3f78eb1f1f\*/
		$sha78 = /\*4182c05028c14b61bffa9d70e60197b0d93df8d4\*/
		$sha79 = /\*e1762dc93654ffa57ab63e6f234ddad60ad33c5e\*/
		$sha80 = /\*66787254569b68970bf7cafc13e0f61aff9759a8\*/
		$sha81 = /\*b30ad7be60b6f556f5982b02f4779609fd68b73c\*/
		$sha82 = /\*2f3c00be0741322af5262f514eebb623d2de5142\*/
		$sha83 = /\*dd6bfdc328017b193160a9a9ff34a3dfa6e67dac\*/
		$sha84 = /\*1e888820524341c3ea40cddc859572165cad2654\*/
		$sha85 = /\*4c2b6b2cbd929dad845adaefffe4e5fb04c66581\*/
		$sha86 = /\*d9692ba3357042fd448bece301043b06a97057ae\*/
		$sha87 = /\*938699a8db8726b779eed1515572598b463d2b71\*/
		$sha88 = /\*4075376f01a344b7517c2588afe180160137fb4a\*/
		$sha89 = /\*e8b1c38298f0df89d6aa9a40d4f63fd08c5e3318\*/
		$sha90 = /\*d7e653342bf503c770d4a142cff53cc83738a3f1\*/
		$sha91 = /\*4bb11a5a24771e69698d1ad579c5b5805a07ef00\*/
		$sha92 = /\*dff7ecc6491beb5f19ed879a14586d184c364e12\*/
		$sha93 = /\*2acdc7f3292d5c5723c478f853442b087b322c0b\*/
		$sha94 = /\*fc8226b5c465b03f9410ef13ea2b1fefa3ee352f\*/
		$sha95 = /\*da6335156f81b56a57b91ec7b8ab24dabaea36c3\*/
		$sha96 = /\*c6ffdc26b44df0a702e97f5c9f9e66b282f9d08d\*/
		$sha97 = /\*2dfd84944fbb2dba259bc409acbee36e9d7c1df8\*/
		$sha98 = /\*a6cb1edbb8c5ca7caadd2a35d3ef3eed4ab2fada\*/
		$sha99 = /\*9f5ba21341fea5d4e2555e3a29bf0dfbfdc23943\*/
		$sha100 = /\*1347cc87c68b0addaeb9e6402fe5b4b7dabe981e\*/
		$sha101 = /\*a9aef1f64d83634f1c474bcd42a5281cb92518f7\*/
		$sha102 = /\*e9d955fe2f16321b5232a1bb900a83fd84c89bec\*/
		$sha103 = /\*602ab4c4ac00b6ddff3b701b0d81018bebcfd081\*/
		$sha104 = /\*5f3a7a5394d04276d288577ccce25e80c208e343\*/
		$sha105 = /\*605b762b1bb4d5ab9376344160a47c9f1f2e175b\*/
		$sha106 = /\*fc94ce267241f124e7b176aae04816b34cbdf935\*/
		$sha107 = /\*20522969eaf14e2b517949d460338eafc3ca9bfc\*/
		$sha108 = /\*59817a51c39036a39988561925b591f4b2bbdf1f\*/
		$sha109 = /\*bb3f33bac710195dbd839157d9d8acc48bb840c6\*/
		$sha110 = /\*c6e058047efee823fae0891af90c398b040684ef\*/
		$sha111 = /\*12ee6977aa19b44b66cde50f6a5e9e3987d137ef\*/
		$sha112 = /\*021a6d96c2558913788ae3c6130fa492a48083dc\*/
		$sha113 = /\*85546c4a110ec46749bc75da5dc5e691612d9af4\*/
		$sha114 = /\*b72fe614a84a6d986279cedf66437f66e57752bf\*/
		$sha115 = /\*a0a4e2ca9f49bd1cdf2fd5188a4735ad8bf8f14d\*/
		$sha116 = /\*3646d39a3ee6f54a19106da0bd5e16675ceea750\*/
		$sha117 = /\*7b88382ab6bd24ba597e07ce9a52c980cd4295bf\*/
		$sha118 = /\*3da4b14def0493218bca6c2b0132df5f59851e7d\*/
		$sha119 = /\*bb13ee4d8e21fc41a68ef940ddb7282ad127712d\*/
		$sha120 = /\*87148e1723083e2fad0c56e0ca8b9e9d99967c0f\*/
		$sha121 = /\*71d1897d14097558631f287ff9575a43fe7fa699\*/
		$sha122 = /\*f4c94c82e64192660791a7285331829a68994f75\*/
		$sha123 = /\*634bd3f14ce65c8e5ccb33d3ab29bf8b463530b5\*/
		$sha124 = /\*6fb8d5fdbe98048d7935797c2d8ce055b2d30cb7\*/
		$sha125 = /\*9dde70da2dea57da254132cc2d1e17d4b5a9399c\*/
		$sha126 = /\*828b8ab597d958f153a270a7f4a1bbf65a39e9ce\*/
		$sha127 = /\*024729b5a3df67e7708e3067b1fd47bae2145271\*/
		$sha128 = /\*45d13d6041a4869b38d44dfd2c21a3b69479cb83\*/
		$sha129 = /\*94a35b8abb99100be94f7f96cf54c2b80c90cb12\*/
		$sha130 = /\*801c8bd1e8edc6eda384c65aaa748102472416ce\*/
		$sha131 = /\*4df35cb2a4b1ce6c0dab545908137d265ae72622\*/
	condition:
		any of them
}

rule cryptoshell_apkguard_a: packer
{
  meta:
    description = "APKGuard/CryptoShell"
    url         = "http://apkguard.io/"
    example     = "d9c98fff427646883ecb457fc2e9d2a8914ba7a9ee194735e0a18f56baa26cca"
    url2        = "http://cryptoshell.io"
    example2    = "d6745c1533b440c93f7bdfbb106470043b23aafdf91506c52332ed192d7b7003"
  strings:
    $attachBaseContextOpcodes = {
        120b            // const/4 v11, 0
        6f20 0100 fe00  // invoke-super {v14, v15}, Landroid/app/Application.attachBaseContext(Landroid/content/Context;)V ; 0x1
        2206 ??00       // new-instance v6, Ljava/io/File; ; 0x180
        6e10 ??00 0e00  // invoke-virtual {v14}, Llctavku/ngbdjdfqf.getFilesDir()Ljava/io/File; ; 0x19
        0c09            // move-result-object v9
        1a0a ??00       // const-string v10, str.mtuECIoALWpjXcVYbOOKBHNTMligrjLQpGFKT.zip ; 0x239c
        7030 ???? 960a  // invoke-direct {v6, v9, v10}, Ljava/io/File.<init>(Ljava/io/File;Ljava/lang/String;)V ; 0xa
        1a09 ??00       // const-string v9, str.UEsDBBQAAAAIAAMAi0tT_4a5ihQAAGArAAALABwAY2xhc3Nlcy5kZXhVVAkAA1Wg....
        7120 ??00 b900  // invoke-static {v9, v11}, Landroid/util/Base64;.decode:(Ljava/lang/String;I)[B // method@0003
        0c02            // move-result-object v2
        2205 ??00       // new-instance v5, Ljava/io/FileOutputStream; // type@0007
        7020 ??00 6500  // invoke-direct {v5, v6}, Ljava/io/FileOutputStream;.<init>:(Ljava/io/File;)V // method@000c
        2201 ??00       // new-instance v1, Ljava/io/BufferedOutputStream; // type@0005
        7020 ??00 5100  // invoke-direct {v1, v5}, Ljava/io/BufferedOutputStream;.<init>:(Ljava/io/OutputStream;)V // method@0006
        6e20 ??00 2100  // invoke-virtual {v1, v2}, Ljava/io/BufferedOutputStream;.write:([B)V // method@0009
        6e10 ??00 0100  // invoke-virtual {v1}, Ljava/io/BufferedOutputStream;.flush:()V // method@0008
        6e10 ??00 0100  // invoke-virtual {v1}, Ljava/io/BufferedOutputStream;.close:()V // method@0007
        6e10 ??00 0600  // invoke-virtual {v6}, Ljava/io/File;.getAbsolutePath:()Ljava/lang/String; // method@000b
        0c03            // move-result-object v3
        6e10 ??00 0e00  // invoke-virtual {v14}, Lyxlhycuqv/weudayy;.getFilesDir:()Ljava/io/File; // method@0019
        0c09            // move-result-object v9
        6e10 ??00 0900  // invoke-virtual {v9}, Ljava/io/File;.getAbsolutePath:()Ljava/lang/String; // method@000b
        0c07            // move-result-object v7
        6e10 ??00 0e00  // invoke-virtual {v14}, Lyxlhycuqv/weudayy;.getClassLoader:()Ljava/lang/ClassLoader; // method@0018
        0c00            // move-result-object v0
        2204 ??00       //  new-instance v4, Ldalvik/system/DexClassLoader; // type@0004
        1209            // const/4 v9, #int 0 // #0
        7050 ??00 3497  // invoke-direct {v4, v3, v7, v9, v0}, Ldalvik/system/DexClassLoader;.<init>:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V // method@0004
        1a09 ??00       // const-string v9, "yabno/blkngwigpd" // string@003d
        6e20 ??00 9400  // invoke-virtual {v4, v9}, Ldalvik/system/DexClassLoader;.loadClass:(Ljava/lang/String;)Ljava/lang/Class; // method@0005
        0c09            // move-result-object v9
        120a            // const/4 v10, #int 0 // #0
        23aa ??00       // new-array v10, v10, [Ljava/lang/Class; // type@0016
        6e20 ??00 a900  // invoke-virtual {v9, v10}, Ljava/lang/Class;.getConstructor:([Ljava/lang/Class;)Ljava/lang/reflect/Constructor; // method@000d
        0c09            // move-result-object v9
        120a            // const/4 v10, #int 0 // #0
        23aa ??00       // new-array v10, v10, [Ljava/lang/Object; // type@0017
        6e20 ??00 a900  // invoke-virtual {v9, v10}, Ljava/lang/reflect/Constructor;.newInstance:([Ljava/lang/Object;)Ljava/lang/Object; // method@0013
        0c09            // move-result-object v9
        5be9 0000       // iput-object v9, v14, Lyxlhycuqv/weudayy;.aaa:Ljava/lang/Object; // field@0000
        54e9 0000       // iget-object v9, v14, Lyxlhycuqv/weudayy;.aaa:Ljava/lang/Object; // field@0000
        6e10 ??00 0900  // invoke-virtual {v9}, Ljava/lang/Object;.getClass:()Ljava/lang/Class; // method@0012
        0c09            // move-result-object v9
        1a0a ??00       // const-string v10, "attachBaseContext" // string@0022
        121b            // const/4 v11, #int 1 // #1
        23bb ??00       // new-array v11, v11, [Ljava/lang/Class; // type@0016
        120c            // const/4 v12, #int 0 // #0
        1c0d ??00       // const-class v13, Landroid/content/Context; // type@0002
        4d0d ????       // aput-object v13, v11, v12
        6e30 ??00 a90b  // invoke-virtual {v9, v10, v11}, Ljava/lang/Class;.getDeclaredMethod:(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method; // method@000e
        0c09            // move-result-object v9
        54ea 0000       // iget-object v10, v14, Lyxlhycuqv/weudayy;.aaa:Ljava/lang/Object; // field@0000
        121b            // const/4 v11, #int 1 // #1
        23bb ??00       // new-array v11, v11, [Ljava/lang/Object; // type@0017
        120c            // const/4 v12, #int 0 // #0
        4d0e ????       // aput-object v14, v11, v12
        6e30 ??00 a90b  // invoke-virtual {v9, v10, v11}, Ljava/lang/reflect/Method;.invoke:(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object; // method@0015
        0e00            // return-void
        0d08            // move-exception v8
        6e10 ??00 0800  // invoke-virtual {v8}, Ljava/lang/Exception;.printStackTrace:()V // method@000f
        28fb            // goto 0073 // -0005
}
  condition:
    $attachBaseContextOpcodes
}

rule appguard_a: packer
{
  meta:
    description = "AppGuard"
  strings:
    $stub = "assets/appguard/"
    $encrypted_dex = "assets/classes.sox"
  condition:
    ($stub and $encrypted_dex)
}
rule dxshield_b: packer
{
  meta:
    description = "DxShield"
  strings:
    $decryptlib = "libdxbase.so"
    $res = "assets/DXINFO.XML"
  condition:
    ($decryptlib and $res)
}
rule secneo_b: packer
{
  meta:
    description = "SecNeo"
  strings:
    $encryptlib1 = "libDexHelper.so"
    $encryptlib2 = "libDexHelper-x86.so"
    $encrypted_dex = "assets/classes0.jar"
  condition:
    any of ($encrypted_dex, $encryptlib2, $encryptlib1)
}
rule dexprotector_b: packer
{
  meta:
    author = "Jasi2169"
    description = "DexProtector"
  strings:
    $encrptlib = "assets/dp.arm.so.dat"
    $encrptlib1 = "assets/dp.arm-v7.so.dat"
    $encrptlib2 = "assets/dp.arm-v8.so.dat"
    $encrptlib3 = "assets/dp.x86.so.dat"
    $encrptcustom = "assets/dp.mp3"
  condition:
    any of ($encrptlib, $encrptlib1, $encrptlib2, $encrptlib3) and $encrptcustom
}
rule apkprotect_a: packer
{
  meta:
    description = "APKProtect"
  strings:
    $key = "apkprotect.com/key.dat"
    $dir = "apkprotect.com/"
    $lib = "libAPKProtect.so"
  condition:
    ($key or $dir or $lib)
}
rule bangcle_a: packer
{
  meta:
    description = "Bangcle"
  strings:
    $main_lib = "libsecexe.so"
    $second_lib = "libsecmain.so"
    $container = "assets/bangcleplugin/container.dex"
    $encrypted_jar = "bangcleclasses.jar"
    $encrypted_jar2 = "bangcle_classes.jar"
  condition:
    any of ($main_lib, $second_lib, $container, $encrypted_jar, $encrypted_jar2)
}
rule kiro_b: packer
{
  meta:
    description = "Kiro"
  strings:
    $kiro_lib = "libkiroro.so"
    $sbox = "assets/sbox"
  condition:
    $kiro_lib and $sbox
}
rule qihoo360_a: packer
{
  meta:
    description = "Qihoo 360"
  strings:
    $a = "libprotectClass.so"
  condition:
    $a and
    not kiro
}
rule jiagu_b: packer
{
  meta:
    description = "Jiagu"
  strings:
    $main_lib = "libjiagu.so"
    $art_lib = "libjiagu_art.so"
  condition:
    ($main_lib or $art_lib)
}
rule qdbh_packer_b: packer
{
  meta:
    description = "'qdbh' (?)"
  strings:
    $qdbh = "assets/qdbh"
  condition:
    $qdbh
}
rule unknown_packer_lib_b: packer
{
  meta:
    description = "'jpj' packer (?)"
  strings:
    $pre_jar = { 00 6F 6E 43 72 65 61 74 65 00 28 29 56 00 63 6F 6D 2F 76 }
    $jar_data = { 2E 6A 61 72 00 2F 64 61 74 61 2F 64 61 74 61 2F 00 2F }
    $post_jar = { 2E 6A 61 72 00 77 00 6A 61 76 61 2F 75 74 69 6C 2F 4D 61 70 00 67 65 74 49 6E 74 00 }
  condition:
    ($pre_jar and $jar_data and $post_jar)
}
rule unicom_loader_b: packer
{
  meta:
    description = "Unicom SDK Loader"
  strings:
    $decrypt_lib = "libdecrypt.jar"
    $unicom_lib = "libunicomsdk.jar"
    $classes_jar = "classes.jar"
  condition:
    ($unicom_lib and ($decrypt_lib or $classes_jar))
}
rule liapp_a: packer
{
  meta:
    description = "LIAPP"
  strings:
    $dir = "/LIAPPEgg"
    $lib = "LIAPPClient.sc"
  condition:
    any of ($dir, $lib)
}
rule app_fortify_b: packer
{
  meta:
    description = "App Fortify"
  strings:
    $lib = "libNSaferOnly.so"
  condition:
    $lib
}
rule nqshield_b: packer
{
  meta:
    description = "NQ Shield"
  strings:
    $lib = "libnqshield.so"
    $lib_sec1 = "nqshield"
    $lib_sec2 = "nqshell"
  condition:
    any of ($lib, $lib_sec1, $lib_sec2)
}
rule tencent_a: packer
{
  meta:
    description = "Tencent"
  strings:
    $decryptor_lib = "lib/armeabi/libshell.so"
    $zip_lib = "lib/armeabi/libmobisecy.so"
    $classpath = "com/tencent/StubShell"
    $mix_dex = "/mix.dex"
  condition:
    ($classpath or $decryptor_lib or $zip_lib or $mix_dex)
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
    ($old_dat or $new_ajm or $ijm_lib)
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
rule medusah_b: packer
{
  meta:
    description = "Medusah"
  strings:
    $lib = "libmd.so"
  condition:
    $lib
}
rule medusah_appsolid_b: packer
{
  meta:
    description = "Medusah (AppSolid)"
  strings:
    $encrypted_dex = "assets/high_resolution.png"
  condition:
    $encrypted_dex and not medusah
}
rule baidu_a: packer
{
  meta:
    description = "Baidu"
  strings:
    $lib = "libbaiduprotect.so"
    $encrypted = "baiduprotect1.jar"
  condition:
    ($lib or $encrypted)
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
rule kony_b: packer
{
  meta:
    description = "Kony"
  strings:
    $lib = "libkonyjsvm.so"
    $decrypt_keys = "assets/application.properties"
    $encrypted_js = "assets/js/startup.js"
  condition:
    $lib and $decrypt_keys and $encrypted_js
}
rule approov_b: packer
{
  meta:
    description = "Aproov"
  strings:
    $lib = "libapproov.so"
    $sdk_config = "assets/cbconfig.JSON"
  condition:
    $lib and $sdk_config
}
rule yidun_a: packer
{
  meta:
    description = "yidun"
  strings:
    $anti_trick = "Lcom/_" // Class path of anti-trick
    $entry_point = "Lcom/netease/nis/wrapper/Entry"
    $jni_func = "Lcom/netease/nis/wrapper/MyJni"
    $lib = "libnesec.so"
  condition:
    (#lib > 1) or ($anti_trick and $entry_point and $jni_func)
}
rule xposed_a: anti_hooking
{
	meta:
		description = "Xposed"
		info        = "xxxxxxx"
		example     = ""
	strings:
		$a = "xposed"
		$b = "rovo89"
	condition:
		all of them
}
rule rootbeer_a: anti_root
{
	strings:
		$rb = "Lcom/scottyab/rootbeer/RootBeerNative;"
		$cls = "RootBeerNative"
		$str = "tool-checker"
	condition:
		all of them
}
rule bitwise_antiskid_a: obfuscator
{
  meta:
    description = "Bitwise AntiSkid"
  strings:
    $credits = "AntiSkid courtesy of Bitwise\x00"
    $array = "AntiSkid_Encrypted_Strings_Courtesy_of_Bitwise"
    $truth1 = "Don't be a script kiddy, go actually learn something. Stealing credit is pathetic, you didn't make this or even contribute to it and you know it."
    $truth2 = "Only skids can't get plaintext. Credits to Bitwise.\x00"
  condition:
    any of them
}
rule dexprotector_c: obfuscator
{
  meta:
    description = "DexProtector"
  strings:
    $method = {
      07 00 02 00 00 00 02 00 00 00 00 00 3E 00 00 00
      12 01 13 00 0E 00 48 00 05 00 E0 00 00 10 01 12
      39 02 2A 00 12 32 D5 63 FF 00 48 03 05 03 D5 33
      FF 00 E1 04 06 08 D5 44 FF 00 48 04 05 04 D5 44
      FF 00 E0 04 04 08 B6 43 E1 04 06 10 D5 44 FF 00
      48 04 05 04 D5 44 FF 00 E0 04 04 10 B6 43 E1 04
      06 18 D5 44 FF 00 48 00 05 04 E0 00 00 18 B6 30
      0F 00 0D 02 39 01 FE FF 12 21 DD 02 06 7F 48 00
      05 02 E1 00 00 08 28 F5 0D 03 28 CB 0D 00 00 00
      20 00 ?? 00 37 00 00 00 02 00 ?? 00 02 01
    }
    $a = "getClass"
    $b = "getDeclaredMethod"
    $c = "invoke"
  condition:
    $method and
    all of ($a, $b, $c)
}
rule a_a: obfuscator
{
  strings:
    $pkg = /L(a{6}|b{6}|c{6}|d{6}|e{6}|f{6}|g{6}|h{6}|i{6}|j{6}|k{6}|l{6}|m{6}|n{6}|o{6}|p{6}|q{6}|r{6}|s{6}|t{6}|u{6}|v{6}|w{6}|x{6}|y{6}|z{6})\/[a-z]{6}/
  condition:
    all of them
}
rule vern_dogservice_a
{
	condition:
		cuckoo.network.dns_lookup(/xsech.xyz/) or	
		cuckoo.network.dns_lookup(/cfglab.com/) or	
		cuckoo.network.dns_lookup(/strckl.xyz/) or	
		cuckoo.network.dns_lookup(/kyhub.com/) or 	
		cuckoo.network.dns_lookup(/adtsk.mobi/) or	
		cuckoo.network.dns_lookup(/ofguide.com/) or 
		cuckoo.network.dns_lookup(/dinfood.com/) or
		cuckoo.network.dns_lookup(/apphale.com/) or
		cuckoo.network.dns_lookup(/offseronline.com/)
}
rule MalignantFeatures_a: jcarneiro
{
	meta:
		description = "This rule detects applications containing any of the following list of potential malignant features"
	strings:
		$a = "2.5.8"
    	$b = "10308"
    	$c = "2.3.7"
    	$d = "2.7.3"
    	$e = "Diego Batt"
    	$j = "2.4.7"
    	$k = "2.7.7"
    	$l = "2.1.8"
    	$m = "2.7.5"
	    $n = "2.7.8"
    	$o = "2.8.8"
    	$p = "2.8.5"
    	$q = "2.2.8"
    	$r = "2.8.7"
    	$s = "2.5.5"
    	$t = "2.6.3"
	condition:
		any of them
}
rule reddrop_a
{
	meta:
		description = "This rule detects malicious samples belonging to Reddrop campaign"
		sample = "76b2188cbee80fffcc4e3c875e3c9d25"
	strings:
		$a_1 = "assets/payPK"
		$a_2 = "assets/F88YUJ4PK"
		$a_3 = "assets/wyzf/res.binPK"
		$a_4 = "assets/yylist.xmlPK"
	condition:
		androguard.service(/com.y.f.jar.pay.UpdateServices/) and
		androguard.service(/com.wyzfpay.service.CoreService/) and
		androguard.receiver(/com.y.f.jar.pay.InNoticeReceiver/) and
		androguard.receiver(/com.jy.publics.JyProxyReceiver/) and
		all of ($a_*)
}
rule appguard_b: packer
{
    meta:
        description = "AppGuard"
    strings:
        $c = "AppGuard0.jar"
        $d = "AppGuard.dgc"
        $e = "libAppGuard.so"
        $f = "libAppGuard-x86.so"
    condition:
        3 of them
}
rule koodous_laaa: official
{
	meta:
		description = "Android.Fakebank"
	condition:
		androguard.package_name("com.ibk.smsmanager") or
		androguard.package_name("com.example.kbtest")
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
rule Title_Santander_a {
	strings:
		$string_1 = /Santander/
		$string_2 = /Spendlytics/
		$string_3 = /SmartBank/
		$string_4 = /Flite/
	condition:
	1 of ($string_*)
}
rule Androguard_Santander_a {
	meta:
		description = "Per Package detection"
	condition:
		androguard.package_name("es.bancosantander.accionistas.uk") or
		androguard.package_name("com.osper.santander") or
		androguard.package_name("uk.co.santander.smartbank") or
		androguard.package_name("uk.co.santander.flite") or
		androguard.package_name("com.santander.kitti") or
		androguard.package_name("uk.co.santander.isasUK") or
		androguard.package_name("uk.co.santander.santanderUK") or
		androguard.package_name("uk.co.santander.businessUK.bb") or
		androguard.package_name("uk.co.santander.spendlytics")
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
rule koodous_maaa: official
{
	meta:
		description = "https://vms.drweb.com/virus/?_is=1&i=15503184"
		sample = ""
	strings:
		$a = "cf89490001"
		$b = "droi.zhanglin"
		$c = "configppgl"
	condition:
		$a or
		$b or
		$c
}
rule fake_google_chrome_a
{
	meta:
		description = "This rule detects fake google chrome apps"
		sample = "ac8d89c96e4a7697caee96b7e9de63f36967f889b35b83bb0fa5e6e1568635f5"
	condition:
		androguard.package_name("com.android.chro.me")
}
rule ahmyth_rat_a
{
	meta:
		description = "This rule detects malicious spawns of Ahmyth RAT"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.service(/ahmyth.mine.king.ahmyth.MainService/) and
		androguard.receiver(/ahmyth.mine.king.ahmyth.MyReceiver/)
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
rule Coinhive_a
{
 strings:
   $a1 = "*rcyclmnrepv*" wide ascii
   $a2 = "*coin-hive*" wide ascii
   $a3 = "*coin-hive.com*" wide ascii
   $a4 = "*com.android.good.miner*" wide ascii
 condition:
   any of them
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
rule rule1_a: mmarrkv_misc
{
	meta:
		description = "Test rule"
	condition:
		androguard.permission(/SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/BIND_ACCESSIBILITY_SERVICE/)
}
rule AndroRat_a
{
        meta:
                description = "ejercicio - yarn - androrat"
        strings:
                $a = "Lmy/app/client/ProcessCommand" wide ascii
                $b = "AndroratActivity" wide ascii
                $c = "smsKeyWord" wide ascii
                $d = "numSMS" wide ascii
        condition:
                $a and ($b or $c or $d)
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
rule koodous_naaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "com.citi.citimobile"
		$m = "com.citibank.mobile.au"
	condition:
		any of them
}
rule possible_miner_test_a
{
	meta:
		description = "This rule detects adb miner "
		sample = "412874e10fe6d7295ad7eb210da352a1"
	strings:
		$a_1 = "loadUrl"
		$a_2 = "file"
		$a_3 = "android_asset"
		$a_4 = "html"
		$a_5 = "webView"
	condition:
		all of ($a_*)
}
rule koodous_oaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "android.intent.action.MULTI_CSC_CLEAR"
		$m = "lgeWapService.prov.persister.INSTALL_BROWSER"
		$k = "android.htc.intent.action.CUSTOMIZATION_CHANGE"
	condition:
		any of them
}
rule koodous_paaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "https://blog.fortinet.com/2017/01/26/deep-analysis-of-android-rootnik-malware-using-advanced-anti-debug-and-anti-hook-part-i-debugging-in-the-scope-of-native-layer"
	strings:
		$a = /com.secshell/
		$b = "secData0.jar"
		$c = "DexInstall"
		$d = "libSecShell.so"
	condition:
 		2 of them
}
rule SuspiciousAdds_a
{
	meta:
		description = "This rule looks for suspicios activity"
	condition:
		androguard.activity(/com.startapp.android.publish.OverlayActivity/i) or androguard.activity(/com.greystripe.sdk.GSFullscreenActivity/i)
}
rule crypto_a: jcarneiro
{
	strings:
		$a = "xmr"
	condition:
		$a
}
rule FakeAngribirds_a
{
	meta:
		description = "This ruleset looks for angribirds not by rovio"
	condition:
		androguard.activity(/com.rovio.fusion/i) and not
		androguard.certificate.sha1("66DA9177253113474F6B3043B89E0667902CF115") 
}
rule koodous_qaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "event_prepared_begin_install"
	condition:
		any of them
		}
rule crypto_b: jcarneiro
{
	strings:
		$a = "pool.minexmr.com"
	condition:
		$a
}
rule koodous_raaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "L_V_loadDone"
	condition:
		any of them
		}
rule koodous_saaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "r_root_true"
	condition:
		any of them
		}
rule koodous_taaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "ptrace"
	condition:
		any of them
}
rule koodous_uaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "ptrace_attach"
	condition:
		any of them
}
rule koodous_vaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "PPP begin"
		$k = "PPP end"
		$m = "PPP Error"
	condition:
		any of them
}
rule FaceAdware_a
{
	meta:
		description = "Adware pretending to be a Whatsapp or Facebook hack."
		sample = "https://analyst.koodous.com/apks?search=3d2f4b7abbf8b80982b0100835427ac8%20%20748de691ed7a407b169ffe102ed6f71e%20%20098c5f83f732e9b22a3e19a6523a5f8d%20%20c81c519a151f2611cc30ee4756c94f30"
	strings:
		$pub_id = "ca-app-pub-5886589216790682/8233759652"
		$pub_id2 = "ca-app-pub-5886589216790682/9710492858"
	condition:
		$pub_id or $pub_id2 
}
rule koodous_waaa: official
{
	meta:
        description = "Rule to catch APKs with package name match with com.app.attacker."
    condition:
        androguard.package_name(/com\.app\.attacker\../)
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
rule edvo_a
{
	strings:
		$a= "EDVO revision 0"
	condition:
		all of them
}
rule testing_a
{
	meta:
		description = "This rule is a test"
	strings:
	  $a1 = "file.separator"
	  $a2 = "java.class.path"
	  $a3 = "java.class.version"
	  $a4 = "java.compiler"
	  $a5 = "java.ext.dirs"
	  $a6 = "java.home"
	  $a7 = "java.io.tmpdir"
	  $a8 = "java.library.path"
	  $a9 = "java.specification.name"
	  $a22 = "java.specification.vendor"
	  $a11 = "java.specification.version"
	  $a33 = "java.vendor"
	  $a44 = "java.vendor.url"
	  $a55 = "java.version"
	  $a66 = "java.vm.name"
	  $a77 = "java.vm.specification.name"
	  $a88 = "java.vm.specification.vendor"
	  $a99 = "java.vm.specification.version"
	  $a00 = "java.vm.vendor"
	  $a23 = "java.vm.version"
	  $a34 = "line.separator"
	  $a45 = "os.arch"
	  $a56 = "os.name"
	  $a78 = "os.version"
	  $a89 = "path.separator"
	  $a09 = "user.dir"
	  $a98 = "user.home"
	  $a87 = "user.name"
	condition:
		all of them
}
rule testing_b
{
	meta:
		description = "This rule is a test"
	strings:
	  $a1 = "file.separator"
	  $a2 = "java.class.path"
	  $a3 = "java.class.version"
	  $a4 = "java.compiler"
	  $a5 = "java.ext.dirs"
	  $a6 = "java.home"
	  $a7 = "java.io.tmpdir"
	  $a8 = "java.library.path"
	  $a9 = "java.specification.name"
	  $a22 = "java.specification.vendor"
	  $a11 = "java.specification.version"
	  $a33 = "java.vendor"
	  $a44 = "java.vendor.url"
	  $a55 = "java.version"
	  $a66 = "java.vm.name"
	  $a77 = "java.vm.specification.name"
	  $a88 = "java.vm.specification.vendor"
	  $a99 = "java.vm.specification.version"
	  $a00 = "java.vm.vendor"
	  $a23 = "java.vm.version"
	  $a34 = "line.separator"
	  $a45 = "os.arch"
	  $a56 = "os.name"
	  $a78 = "os.version"
	  $a89 = "path.separator"
	  $a09 = "user.dir"
	  $a98 = "user.home"
	  $a87 = "user.name"
	  $b1 = "1xRTT"
	  $b2 = "CDMA"
	  $b3 = "EDGE"
	  $b4 = "eHRPD"
	  $b5 = "EDVO revision 0"
	  $b6 = "EDVO revision A"
	  $b7 = "EDVO revision B"
	  $b8 = "GPRS"
	  $b9 = "HSDPA"
	  $b11 = "HSPA"
	  $b12 = "HSPA+"
	  $b13 = "HSUPA"
	  $b14 = "iDen"
	  $b15 = "LTE"
	  $b16 = "UMTS"
	  $b17 = "CDMA"
	  $b18 = "GSM"
	  $b19 = "SIP"
	condition:
		all of them
}
rule testing_c
{
	meta:
		description = "This rule is a test"
	strings:
		$a = "install"
	condition:
		all of them
}
rule whatsdog_a: test
{
	meta:
		description = "Fake Whatsdog apps"
	condition:		
		androguard.app_name("WhatsDog") and 
		not androguard.certificate.sha1("006DA2B35407A5A017F04C4C675B05D3E77808C9")
}
rule plantsvszombies_a:SMSFraud
{
	meta:
		sample = "ebc32e29ceb1aba957e2ad09a190de152b8b6e0f9a3ecb7394b3119c81deb4f3"
	condition:
		androguard.certificate.sha1("2846AFB58C14754206E357994801C41A19B27759")
}
rule FakeFacebook_a
{
	meta:
		description = "Fake Facebook applications"
	condition:
		androguard.app_name("Facebook") and
		not androguard.certificate.sha1("8A3C4B262D721ACD49A4BF97D5213199C86FA2B9")	
}
rule SMSFraud_a
{
	condition:
		androguard.certificate.issuer(/\/C=UK\/ST=Portland\/L=Portland\/O=Whiskey co\/OU=Whiskey co\/CN=John Walker/)
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
rule smsfraud_a
{
	meta:
		description = "This rule detects apks related with sms fraud"
		sample = "79b35a99f16de6912d6193f06361ac8bb75ea3a067f3dbc1df055418824f813c"
	condition:
		androguard.certificate.sha1("1B70B4850F862ED0D5D495EC70CA133A4598C007")
}
rule packers_a
{
	meta:
		description = "packers"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_b = "libmobisecy1"
	condition:
		$strings_b 
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
rule koodous_xaaa: official
{
	meta:
		description = "http://researchcenter.paloaltonetworks.com/2015/10/chinese-taomike-monetization-library-steals-sms-messages/"
	condition:
		androguard.url("http://112.126.69.51/2c.php")
}
rule koodous_yaaa: official
{
	meta:
		description = "This rule detects the fake installers."
		testing = "yes"
		sample = "6e57a0b0b734914da334471ea3cd32b51df52c2d17d5d717935373b18b6e0003" //Fake avast
	condition:
		androguard.activity(/com\.startapp\.android\.publish\.AppWallActivity/) and
		androguard.activity(/com\.startapp\.android\.publish\.list3d\.List3DActivity/)		
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
rule ggtracker_a: trojan
{
	meta:
		description = "Android.Ggtracker is a Trojan horse for Android devices that sends SMS messages to a premium-rate number. It may also steal information from the device."
		sample = "8c237092454584d0d6ae458af70dc032445b866fd5913979bbad576f42556577"
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.url("http://ggtrack.org/SM1c?device_id=")
}
rule koodous_zaaa: official
{
	meta:
		description = "Ads and pron. Gets to remote host(porn) http://hwmid.ugameok.hk:8803/vvd/"
	strings:
		$a = "http://hwmid.ugameok.hk:8803/vvd/main?key="
	condition:
		androguard.certificate.sha1("C2:E4:C2:C7:AA:E9:ED:9C:C9:4B:B0:12:BA:DB:52:26:D1:27:87:42") or $a
}
rule taskhijack4_a: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
	strings:
		$a = "allowTaskReparenting"
	condition:
		$a 
}
rule taskhijack3_b: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
	strings:
		$a = "taskAffinity"
	condition:
		$a 
}
rule taskhijack2_a: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
	strings:
		$a = "TaskStackBuilder"
	condition:
		$a 
}
rule Posible_bypass_Screenlock_a
{
	meta:
		description = "Bypass_Screenlock"
	condition:
		androguard.permission(/android.permission.DISABLE_KEYGUARD/)
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
rule dowgin_c:adware
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
rule AntiVM_a
{
	meta:
		description = "This rule detects any application that checks VM environment"
	strings:
		$a = /emulator/i
		$b = /goldfish/i
		$c = "DEVICE_ID_EMULATOR"
		$e = "X11 terminal emulator"
		$f = "com/google/android/gms/internal"
		$g = "Only emulators with Google APIs include Google Play Services"
		$h = "com/google/android/gms/ads"
		$i = "com/mixpanel/android/viewcrawler/ViewCrawler$LifecycleCallbacks"
	condition:
		($a or $b or $c) and not ($e or $f or $g or $h or $i)
}
rule fakeInstaller_c
{
	meta:
		description = "The apps developed by this guy are fakeinstallers"
		one_sample = "fb20c78f51eb781d7cce77f501ee406a37327145cf43667f8dc4a9d77599a74d"
	condition:
		androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")
}
rule libAPKProtect_a: packer
{
	meta:
		description = "Packer libAPKProtect"
	strings:
		$a = "APKMainAPP"
		$b = "libAPKProtect"
	condition:
		any of them
}
rule libprotectClass_b: packer
{
	meta:
		description = "Packer libProtect"
	strings:
		$a = "libprotectClass"
	condition:
		$a
}
rule SMSFraud_c: chinese
{
	meta:
		description = "Simulate apps with chinese name to make sms fraud."
		sample = "64f4357235978f15e4da5fa8514393cf9e81fc33df9faa8ca9b37eef2aaaaaf7"
	condition:
		androguard.certificate.sha1("24C0F2D7A3178A5531C73C0993A467BE1A4AF094")
}
rule chinese_setting_a
{
	meta:
		sample = "ff53d69fd280a56920c02772ceb76ec6b0bd64b831e85a6c69e0a52d1a053fab"
	condition:
		androguard.package_name("com.anrd.sysservices") and
		androguard.certificate.issuer(/localhost/)
}
rule chineseporn_a: player
{
	meta:
		sample = "4a29091b7e342958d9df00c8a37d58dfab2edbc06b05e07dcc105750f0a46c0f"
	condition:
		androguard.package_name("com.mbsp.player") and
		androguard.certificate.issuer(/O=localhost/)
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
rule collectors_b
{
	meta:
		description = "Filter for remote controlled malwares"
	condition:
		androguard.permission(/android.permission.INTERNET/)
		and androguard.permission(/android.permission.READ_SMS/)
		and androguard.permission(/android.permission.READ_PHONE_STATE/)
		and androguard.permission(/android.permission.ACCESS_WIFI_STATE/)
		and androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
		and androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
		and not androguard.permission(/android.permission.SEND_SMS/)
}
rule sms_malwares_nograiny_a
{
	meta:
		description = "SMS malwares catcher"
	condition:
		androguard.permission(/android.permission.SEND_SMS/)
}
rule pletor_a: ransomware
{
	meta:
		description = "This rule detects pletor ransomware, crated by ccm "
	strings:
	$S_11_55102 = { 55 ?? ?? ?? 38 ?? 07 00 54 ?? ?? ?? 6e 10 ?? ?? ?? 00 54 ?? ?? ?? 6e 10 ?? ?? ?? 00 0c ?? 6e 10 ?? ?? ?? 00 0c ?? 71 30 ?? ?? ?? ?? 0c ?? 52 ?? ?? 00 52 ?? ?? 00 6e 30 ?? ?? ?? ?? 54 ?? ?? ?? 13 ?? 5a 00 6e 20 ?? ?? ?? 00 54 ?? ?? ?? 6e 20 ?? ?? ?? 00 54 ?? ?? ?? 6e 10 ?? ?? ?? 00 12 ?? 5c ?? ?? ?? 0e 00 }
$S_11_7046 = { 70 10 ?? ?? 03 00 6e 10 ?? ?? 04 00 0c 00 5b 30 ?? ?? 5b 35 ?? ?? 54 30 ?? ?? 1a 01 ?? ?? 12 02 6e 30 ?? ?? 10 02 0c 00 5b 30 ?? ?? 0e 00 }
$S_10_6262 = { 62 ?? ?? ?? 6e 10 ?? ?? ?? 00 0c 01 72 10 ?? ?? 01 00 0a ?? 38 ?? 13 00 72 10 ?? ?? 01 00 0c 00 1f 00 ?? ?? 54 ?? ?? ?? 6e 20 ?? ?? 02 00 0a ?? 12 ?? 32 ?? ed ff 12 ?? 0f ?? 12 ?? 28 fe }
$S_11_1282 = { 12 12 6a 02 ?? ?? 1a ?? ?? ?? 6e 20 ?? ?? ?? 00 0c 00 1f 00 ?? 00 1a 01 ?? ?? 6e 30 ?? ?? 20 01 0c ?? 5b ?? ?? ?? 54 ?? ?? ?? 6e 10 ?? ?? ?? 00 22 ?? ?? ?? 22 ?? ?? ?? 70 20 ?? ?? ?? 00 70 20 ?? ?? ?? 00 6e 10 ?? ?? ?? 00 6f 10 ?? 00 03 00 0e 00 }
$S_11_5450 = { 54 30 ?? ?? 71 10 ?? ?? 00 00 0c 00 1a 01 ?? ?? 12 02 72 30 ?? ?? 10 02 0a 00 39 00 0b 00 54 30 ?? ?? 71 10 ?? ?? 00 00 0c 00 71 10 ?? ?? 00 00 0e 00 }
$S_10_22126 = { 22 ?? ?? 00 54 ?? ?? 00 70 20 ?? 00 ?? 00 6e 10 ?? 00 ?? 00 54 ?? ?? 00 1a ?? ?? 00 12 ?? 6e 30 ?? 00 ?? ?? 0c ?? 1a ?? ?? ?? 12 ?? 71 30 ?? ?? ?? ?? 1a ?? ?? ?? 12 ?? 71 30 ?? ?? ?? ?? 54 ?? ?? 00 6e 10 ?? 00 ?? 00 0e 00 0d 00 1a ?? ?? 00 22 ?? ?? 00 1a ?? ?? 00 70 20 ?? ?? ?? 00 6e 10 ?? ?? 00 00 0c ?? 6e 20 ?? ?? ?? 00 0c ?? 6e 10 ?? ?? ?? 00 0c ?? 71 20 ?? 00 ?? 00 28 e6 }
$S_33_6f24 = { 6f 10 ?? 00 01 00 54 10 ?? ?? 6e 10 ?? ?? 00 00 12 00 6a 00 ?? ?? 0e 00 }
$S_12_5488 = { 54 ?? ?? ?? 71 10 ?? ?? ?? 00 0c ?? 1a ?? ?? ?? 12 ?? 72 30 ?? ?? ?? ?? 0a ?? 39 ?? 1e 00 63 ?? ?? ?? 39 ?? 1a 00 22 00 ?? 00 54 ?? ?? ?? 1c 02 ?? ?? 70 30 ?? ?? 10 02 15 01 00 10 6e 20 ?? ?? 10 00 15 01 02 00 6e 20 ?? ?? 10 00 54 ?? ?? ?? 6e 20 ?? ?? 01 00 0e 00 }
$S_28_6336 = { 63 ?? ?? ?? 39 ?? 0f 00 22 00 ?? 00 70 10 ?? ?? 00 00 1c 01 ?? ?? 6e 30 ?? ?? ?? 01 6e 20 ?? ?? ?? 00 0e 00 }
$S_10_15166 = { 15 ?? 00 10 22 ?? ?? 00 1c ?? ?? ?? 70 30 ?? 00 ?? ?? 54 ?? ?? ?? 6e 20 ?? 00 ?? 00 0a ?? 39 ?? 18 00 22 ?? ?? 00 70 10 ?? ?? ?? 00 1c ?? ?? ?? 6e 30 ?? ?? ?? ?? 6e 10 ?? ?? ?? 00 0a ?? b6 ?? 6e 20 ?? ?? ?? 00 6e 20 ?? ?? ?? 00 0e 00 54 ?? ?? ?? 1a ?? ?? ?? 12 ?? 72 30 ?? ?? ?? ?? 0a ?? 39 ?? f6 ff 54 ?? ?? ?? 1a ?? ?? ?? 12 ?? 71 30 ?? ?? ?? ?? 22 00 ?? 00 1a ?? ?? ?? 1a ?? ?? ?? 71 10 ?? ?? ?? 00 0c ?? 70 30 ?? ?? ?? ?? 6e 10 ?? ?? 00 00 0a ?? b6 ?? 6e 20 ?? ?? ?? 00 6e 20 ?? ?? ?? 00 28 d4 }
$S_11_7138 = { 71 00 ?? ?? 00 00 0c 00 22 01 ?? ?? 70 20 ?? ?? 71 00 16 02 00 00 16 04 64 00 62 06 ?? ?? 78 07 ?? ?? 00 00 0e 00 }
$S_10_1a66 = { 1a ?? ?? ?? 1a ?? ?? ?? 71 20 ?? ?? ?? 00 54 ?? ?? ?? 1a ?? ?? ?? 12 ?? 71 30 ?? ?? ?? ?? 63 ?? ?? ?? 39 ?? 0f 00 22 00 ?? 00 70 10 ?? ?? 00 00 1c 01 ?? ?? 6e 30 ?? ?? ?? 01 6e 20 ?? ?? ?? 00 0e 00 }
$S_11_5256 = { 52 ?? ?? ?? 71 10 ?? ?? ?? 00 0c ?? 5b ?? ?? ?? 54 ?? ?? ?? 38 ?? 07 00 54 ?? ?? ?? 6e 20 ?? ?? ?? 00 0e 00 0d 00 54 ?? ?? ?? 6e 10 ?? ?? ?? 00 12 ?? 5b ?? ?? ?? 28 f6 }
$S_11_1248 = { 12 02 12 01 70 10 ?? ?? 03 00 5b 32 ?? ?? 71 00 ?? ?? 00 00 0a 00 59 30 ?? ?? 5c 31 ?? ?? 5b 32 ?? ?? 5c 31 ?? ?? 5b 34 ?? ?? 5b 35 ?? ?? 0e 00 }
$S_11_2244 = { 22 00 ?? ?? 70 20 ?? ?? ?? 00 22 01 ?? ?? 1a 02 ?? ?? 70 30 ?? ?? ?? 02 6e 20 ?? ?? 10 00 54 31 ?? ?? 72 20 ?? ?? 01 00 0c ?? 11 ?? }
$S_12_16168 = { 16 08 ?? 00 12 12 1a ?? ?? ?? 6e 20 ?? ?? ?? 00 0c ?? 1f ?? ?? 00 1a 01 ?? ?? 6e 30 ?? ?? ?? 01 0c ?? 5b ?? ?? ?? 54 ?? ?? ?? 6e 10 ?? ?? ?? 00 5b aa ?? ?? 6a 02 ?? ?? 1a ?? ?? ?? 12 ?? 6e 30 ?? ?? ?? ?? 0c ?? 5b ?? ?? ?? 6f 10 ?? 00 0a 00 71 00 ?? ?? 00 00 0c 00 22 01 ?? ?? 70 20 ?? ?? a1 00 16 02 00 00 16 04 ?? 00 62 06 ?? ?? 78 07 ?? ?? 00 00 22 01 ?? ?? 70 20 ?? ?? a1 00 62 06 ?? ?? 04 82 04 84 78 07 ?? ?? 00 00 22 ?? ?? ?? 22 ?? ?? ?? 70 20 ?? ?? ?? 00 70 20 ?? ?? ?? 00 6e 10 ?? ?? ?? 00 0e 00 }
$S_11_1a68 = { 1a ?? ?? ?? 1a ?? ?? ?? 71 20 ?? ?? ?? 00 54 ?? ?? ?? 1a ?? ?? ?? 12 ?? 71 30 ?? ?? ?? ?? 71 00 ?? ?? 00 00 0c 00 22 01 ?? ?? 70 20 ?? ?? 71 00 16 02 00 00 16 04 ?? 00 62 06 ?? ?? 78 07 ?? ?? 00 00 0e 00 }
$S_11_2282 = { 22 ?? ?? ?? 54 ?? ?? ?? 71 10 ?? ?? ?? 00 0c ?? 70 20 ?? ?? ?? 00 6e 10 ?? ?? ?? 00 0e 00 0d 00 1a ?? ?? ?? 22 ?? ?? ?? 1a ?? ?? ?? 70 20 ?? ?? ?? 00 6e 10 ?? ?? 00 00 0c ?? 6e 20 ?? ?? ?? 00 0c ?? 6e 10 ?? ?? ?? 00 0c ?? 71 20 ?? ?? ?? 00 28 e6 }
$S_12_12112 = { 12 ?? 70 10 ?? ?? ?? 00 22 ?? ?? ?? 70 10 ?? ?? ?? 00 5b ?? ?? ?? 22 ?? ?? ?? 70 10 ?? ?? ?? 00 5b ?? ?? ?? 12 ?? 23 ?? ?? ?? 1a ?? ?? ?? 4d ?? ?? ?? 71 10 ?? ?? ?? 00 0c ?? 5b ?? ?? ?? 1a ?? ?? ?? 6e 30 ?? ?? ?? ?? 0c ?? 5b ?? ?? ?? 71 00 ?? ?? 00 00 0c ?? 6e 10 ?? ?? ?? 00 0c 00 22 01 ?? ?? 70 20 ?? ?? 01 00 70 20 ?? ?? ?? 00 0e 00 }
	condition:
		16 of them
}
rule wormHole_a
{
	meta:
		description = "Wormhome vulnerability found in com.qihoo.secstore con GPlay. After app launch, a SimpleWebServer service is called listening to 0.0.0.0:38517. It uses yunpan to upload files and get a 360 domain. App protected by proguard."
	strings:
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
rule Twittre_a
{
    condition:
        androguard.certificate.sha1("CEEF7C87AA109CB678FBAE9CB22509BD7663CB6E") and not
		androguard.certificate.sha1("40F3166BB567D3144BCA7DA466BB948B782270EA") //original
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
rule Adware_c: test
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
rule dasho_a: ccm
{
	meta:
		description = "This rule detects dasho obfuscated apps"
		S_37_1270 = " { 12 00 6e 10 ?? ?? ?? 00 0c 02 21 23 32 30 10 00 49 01 02 00 dd 04 ?? 5f b7 14 d8 ?? ?? 01 d8 01 00 01 8e 44 50 04 02 00 01 10 28 f1 12 00 71 30 ?? ?? 02 03 0c 00 6e 10 ?? ?? 00 00 0c 00 11 00 0d 00 12 00 28 fd }		"
	strings:
		$S_127_7156 = { 71 00 ?? ?? 00 00 0b 00 18 02 80 ?? ?? ?? 56 01 00 00 31 00 00 02 3a 00 10 00 22 00 ?? ?? ?? ?? ?? ?? ?? ?? 71 20 ?? ?? 21 00 0c 01 70 20 ?? ?? 10 00 27 00 0d 00 0e 00 }
		$S_371_7158 = { 71 00 ?? ?? 00 00 0b 00 18 02 80 ?? ?? ?? 56 01 00 00 31 00 00 02 3a 00 11 00 22 00 ?? ?? ?? 01 ?? ?? ?? 02 ?? ?? 71 20 ?? ?? 21 00 0c 01 70 20 ?? ?? 10 00 27 00 0d 00 0e 00 }
	condition:
		all of them
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
rule curiosity_b
{
	meta:
		description = "Rule to detect the curiosity malware."
		sample = "6bbaf87fe4e591399897655356911c113678c6e19d98b8b0bd01a4f5e362419e"
	strings:
		$a = "if u want to download spy application please click on :  http://185.38.248.94/api/Service/DownloadEn"
		$b = "Hello I found your private photos here  http://bit.ly/2abgToi  click to see"
		$c = /s ici http:\/\/bit\.ly\/2a9JWWk clique pour les voir/
	condition:
		androguard.url(/185\.38\.248\.94\/messages/) and androguard.permission(/vdsoft.spying.sjin.permission.C2D_MESSAGE/) or $b or $a or $c
}
rule mirai_20161004_a: malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects Mirai samples - 20161004"
        strings:
                $mirai_00 = "/dev/null"
        		$mirai_01 = "LCOGQGPTGP"
        condition:
                uint32(0) == 0x464c457f and
                all of ($mirai_*)
}
rule kaiten_std2_a: malware
{
	meta:
		author = "@h3x2b <tracker@h3x.eu>"
		description = "Detects STDbot samples - 20161009"
	strings:
		$std_00 = "shitteru koto dake"
		$std_01 = "nandemo wa shiranai wa yo"
	condition:
		uint32(0) == 0x464c457f and
		all of ($std_*)
}
rule kaiten_std_a: malware
{
	meta:
		author = "@h3x2b <tracker@h3x.eu>"
		description = "Detects STDbot samples - 20161009"
	strings:
		$irc_00 = "CONNECT"
		$irc_01 = "NICK"
		$irc_02 = "PING"			 
		$irc_03 = "JOIN"
		$std_00 = ":>bot +std"
		$std_01 = "PRIVMSG"
		$std_02 = "[STD]Hitting"
	condition:
		uint32(0) == 0x464c457f and
		all of ($irc_*) and
		all of ($std_*)
}
rule notcompatible_a: ccm
{
	meta:
		description = "This rule detects notcompatible android malware, using common code signature method"
	strings:
	$S_3_5272 = { 52 52 ?? 00 b1 62 71 10 ?? ?? 02 00 0c 00 52 52 ?? 00 b1 62 23 21 ?? 00 54 52 ?? 00 6e 10 ?? ?? 02 00 0c 02 12 03 52 54 ?? 00 b1 64 71 54 ?? ?? 62 31 6e 20 ?? ?? 10 00 5b 50 ?? 00 52 52 ?? 00 b1 62 59 52 ?? 00 0e 00 }
	$S_3_5438 = { 54 20 ?? 00 6e 20 ?? 00 30 00 54 20 ?? 00 54 21 ?? 00 6e 10 ?? ?? 01 00 0a 01 de 01 01 04 6e 20 ?? ?? 10 00 0e 00 }
	$S_3_1276 = { 12 03 52 42 ?? 00 b0 72 71 10 ?? ?? 02 00 0c 00 54 42 ?? 00 6e 20 ?? ?? 32 00 54 42 ?? 00 6e 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 20 00 23 71 ?? 00 71 57 ?? ?? 65 31 6e 20 ?? ?? 10 00 5b 40 ?? 00 52 42 ?? 00 b0 72 59 42 ?? 00 0e 00 }
	$S_3_7030 = { 70 10 ?? ?? 01 00 12 00 59 10 ?? 00 52 10 ?? 00 71 10 ?? ?? 00 00 0c 00 5b 10 ?? 00 0e 00 }
	$S_3_1240 = { 12 01 52 32 ?? 00 39 02 04 00 07 10 11 00 54 30 ?? 00 39 00 04 00 07 10 28 fa 54 02 ?? 00 32 42 f7 ff 54 00 ?? 00 28 f6 }
	$S_3_1a90 = { 1a 00 ?? ?? 6e 10 ?? 00 04 00 0c 01 6e 20 ?? ?? 10 00 0a 00 38 00 0c 00 22 00 ?? 00 1c 01 ?? 00 70 30 ?? 00 30 01 6e 20 ?? 00 03 00 1a 00 ?? ?? 6e 10 ?? 00 04 00 0c 01 6e 20 ?? ?? 10 00 0a 00 38 00 0c 00 22 00 ?? 00 1c 01 ?? 00 70 30 ?? 00 30 01 6e 20 ?? 00 03 00 0e 00 }
	$S_3_12150 = { 12 12 12 03 52 64 ?? 00 39 04 03 00 0e 00 54 60 ?? 00 12 01 38 00 fc ff 54 04 ?? 00 33 74 39 00 39 01 06 00 54 04 ?? 00 5b 64 ?? 00 54 04 ?? 00 39 04 04 00 5b 61 ?? 00 54 04 ?? 00 39 04 21 00 01 25 38 01 20 00 01 24 b5 54 38 04 05 00 12 04 5b 14 ?? 00 54 04 ?? 00 38 04 17 00 01 24 38 01 16 00 b5 42 38 02 06 00 54 02 ?? 00 5b 12 ?? 00 52 62 ?? 00 d8 02 02 ff 59 62 ?? 00 28 c8 01 35 28 e1 01 34 28 e2 01 34 28 eb 01 32 28 eb 07 01 54 00 ?? 00 28 c0 }
	$S_3_1272 = { 12 02 54 53 ?? 00 39 03 03 00 0f 02 54 53 ?? 00 1a 04 ?? ?? 6e 20 ?? 00 43 00 0c 00 1f 00 ?? 00 6e 10 ?? 00 00 00 0c 01 38 01 f1 ff 6e 10 ?? 00 01 00 0a 03 38 03 eb ff 6e 10 ?? 00 01 00 0a 02 59 52 ?? 00 12 12 28 e2 }
	condition:
		7 of them
}
rule kemoge_a: signatures
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
rule Fake_SuperCell_a {
    meta:
        description = "This rule aims to detect fake games from SuperCell. Current list of games included: Clash of Clans, Clash Royale, Hay Day"
    condition:
		(androguard.app_name(/clash royale/i) 
		and not 
		androguard.certificate.sha1("2E18D3F8726B1DE631322716518FB2AEC2EBEB9E")) 
		or (androguard.certificate.sha1("456120D30CDA8720255B60D0324C7D154307F525") 
		and not androguard.app_name(/clash of clans/i)) 
		or (androguard.certificate.sha1("1E7C404B0EE0749CF936606C3EC34CF9D3283BE3") 
		and not androguard.app_name(/hay day/i)) 
		or (androguard.app_name(/boom beach/i) 
		and not androguard.certificate.sha1("C568F735B129423014938283809A36DEA8EBD3A4"))
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
rule spynote_variants_a
{
	meta:
		description = "Yara rule for detection of different Spynote Variants"
		source = " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "SERVER_IP" nocase
		$str_2 = "SERVER_NAME" nocase
		$str_3 = "content://sms/inbox"
		$str_4 = "screamHacker" 
		$str_5 = "screamon"
	condition:
		androguard.package_name("dell.scream.application") or 
		androguard.package_name("com.spynote.software.stubspynote") or
		androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB") or
		all of ($str_*)
}
rule koodous_baaaa: official
{
	meta:
		description = "This rule detects malicious apps with DroidJack components"
		sample = "51b1872a8e2257c660e4f5b46412cb38"
	condition:
		androguard.package_name("net.droidjack.server") and
		androguard.service(/net\.droidjack\.server\./)
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
rule Faketoken_a: Test {
	meta: 
		description = "Ruleset to detect faketoken malware"
	condition:
		network.hosts = "185.48.56.239"
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
rule fake_framaroot_a
{
	meta:
		description = "This rule detects fake framaroot apks"
		sample = "41764d15479fc502be6f8b40fec15f743aeaa5b4b63790405c26fcfe732749ba"
	condition:
		androguard.app_name(/framaroot/i) and
		not androguard.certificate.sha1("3EEE4E45B174405D64F877EFC7E5905DCCD73816")
}
rule locker_a: ransomware
{
	meta:
		description = "This rule detects ransomware apps"
		sample = "41764d15479fc502be6f8b40fec15f743aeaa5b4b63790405c26fcfe732749ba"
	condition:
		androguard.package_name("com.simplelocker")
}
rule Banker_b
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
rule dropper_b
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
rule dropper_c {
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
rule PluginPanthom_a
{
	meta:
		description = "This rule detects pluginpanthom"
		report = "From Palo Alto Networks http://researchcenter.paloaltonetworks.com/2016/11/unit42-pluginphantom-new-android-trojan-abuses-droidplugin-framework/"
	strings:
		$a = "1519j010g4.iok.la"
		$b = "58.222.39.215:8088/dmrcandroid/ws/httpsData/command"
	condition:
		($a and $b) or (
		androguard.url("1519j010g4.iok.la") and
		androguard.url("58.222.39.215:8088/dmrcandroid/ws/httpsData/command")
		)
}
rule smsfraud_b
{
	meta:
		description = "This rule detects several sms fraud applications"
		sample = "ab356f0672f370b5e95383bed5a6396d87849d0396559db458a757fbdb1fe495"
    condition:
		cuckoo.network.dns_lookup(/waply\.ru/) or cuckoo.network.dns_lookup(/depositmobi\.com/)
}
rule SMSPay_a: chinese_porn
{
	meta:
		description = "This rule detects the SMSPay apps"
		sample = "e0fcfe3cc43e613ec733c30511492918029c6c76afe8e9dfb3b644077c77611a"
	condition:
		androguard.certificate.sha1("42867A29DCD05B048DBB5C582F39F8612A2E21CD")
}
rule koodous_caaaa: official
{
	meta:
		description = "looking for root exploit"
		sample = "16de78a5bbd91255546bfbb3565fdbe4c9898a16062c87dbb1cf24665830bbe"
	strings:
                $1 = "Get Root success"
                $2 = "libhxy"
                $3 = "libxy_arm64.so"
                $4 = "firewall"
                $5 = "busybox"
    condition:
                all of ($*)
}
rule construct_a: official
{
	meta:
		description = "looking for root exploit - constructeur"
		sample = "16de78a5bbd91255546bfbb3565fdbe4c9898a16062c87dbb1cf24665830bbe"
	strings:
                $_1 = "asus"
                $_2 = "huawei"
                $_3 = "zte"
                $_4 = "htc"
                $_5 = "sonyericsson"
    condition:
                all of ($_*)
}
rule sensual_woman_b: chinese
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
rule SMSSend_c
{
	strings:
		$a = "bd092gcj"
		$b = "6165b74d-2839-4dcd-879c-5e0204547d71"
		$c = "SELECT b.geofence_id"
		$d = "_ZN4UtilD0Ev"
	condition:
		all of them
}
rule SMSSend2_c
{
	strings:
		$a = "SHA1-Digest: zjwp/bYwUC5kfWetYlFwr/EuHac="
		$b = "style_16_4B4B4B"
		$c = "style_15_000000_BOLD"
	condition:
		all of them
}
rule AntiDebugger_a
{
	strings:
		$a = "/proc/%d/mem"
		$b = "/proc/%d/pagemap"
		$c = "inotify_init"
		$d = "strace"
		$e = "gdb"
		$f = "ltrace"
		$g = "android_server"
		$h = "dvmDbgActive"
	condition:
		($a or $b or $c) or ($d and $e and $f) or $g or $h
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
rule dropper_d
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
rule RazorPayActivity_a
{
	meta:
		description = "All RazorPay SDK Apps"
	condition:
		androguard.activity("com.razorpay.CheckoutActivity")		
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
rule dexguard_a: obfuscator
{
  meta:
    description = "DexGuard"
  strings:
    $opcodes = {
      00 06 00 01 00 03 00 00 00 00 00 00 00
      [20-65]
      0c 01
      12 12
      23 22 ?? ??
      1c 03 ?? ??
      12 04
      4d 03 02 04
      6e 3? ?? ?? 10 02
      0c 00
      62 01 ?? ??
      12 12
      23 22 ?? ??
      12 03
      4d 05 02 03
      6e 3? ?? ?? 10 02
      0c 00
      1f 00 ?? ??
      11 00
    }
    $a = "getClass"
    $b = "getDeclaredMethod"
    $c = "invoke"
  condition:
    $opcodes and
    all of ($a, $b, $c)
}
rule bankbot_a
{
	meta:
		description = "This rule detects the bankbot app based on various info"
		sample = "b3b4afbf0e2cbcf17b04d1a081517a8f3bcb1d7a4b761ba3e3d0834bd3c96f88"
	condition:
		androguard.package_name("com.tvone.untoenynh") or
		androguard.certificate.sha1("4126E5EE9FBD407FF49988F0F8DFAA8BB2980F73") or
		androguard.url(/37.1.207.31\api\?id=7/)
}
rule BankingTrojan_a
{
	meta:
		description = "This rule detects Banking Trojan missusing Accessibility services"
		sample = "4da711976f175d67c5a212567a070348eead1b6fbb1af184c50fdbbefa743f0f"
	strings:
		$required_1 = "getEnabledAccessibilityServiceList"
		$required_4 = "performAction"
		$required_5 = "getContentDescription"
		$required_6 = "getDefaultSmsPackage"
		$required_7 = "removeViewImmediate"
		$required_8 = "getDisplayOriginatingAddress"
		$required_9 = "isAdminActive"		
	condition:
		all of ($required_*) and 
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.EXPAND_STATUS_BAR/) and
		androguard.permission(/android.permission.READ_SMS/)
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
rule Banker_c: Cosmetiq
{
	strings:
		$c2_prefix = "{\"to\":"
		$c2_mid = "\",\"body\":"
		$c2_suffix = "php\"},"
		$com1 = "upload_sms"
		$com2 = "send_sms"
		$com3 = "default_sms"
		$com4 = "sms_hook"
		$com5 = "gp_dialog_password"
		$com6 = "gp_password_visa"
		$com7 = "gp_password_master"
	condition:
		all of ($c2_*)
		and 2 of ($com*) 
		and androguard.permission(/android.permission.RECEIVE_SMS/)
		and androguard.permission(/android.permission.GET_TASKS/)
		and androguard.permission(/android.permission.READ_SMS/)
}
rule Banker2_b: Cosmetiq by Name
{
	condition:
		androguard.package_name("cosmetiq.fl")
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
rule limeUrls_a
{
	meta:
		description = "Ruleset containing c&c servers used by the Lime trojan." 
	strings:
		$site1 = "limeox.ru" 
		$site2 = "3amutka.ru"
		$site3 = "11.serj1228.aux.su"
		$site4 = "185.87.193.242" 
		$site5 = "driver-free.biz" 
		$site6 = "gbb1.ru"
		$site7 = "95.183.13.146"
		$site8 = "jolit.ga"
		$site9 = "g.xenon.myjino.ru"
		$site10 = "trino.myjino.ru"
		$site11 = "amigolite.ru"
		$site12 = "admin25.tw1.su"
		$site13 = "wertik-dok2.myjino.ru"
		$site14 = "deram.myjino.ru"
		$site15 = "44448888.ru" 
		$site16 = "http://ltnari3g.beget.tech/"
	condition:
		any of them or (androguard.activity("app.six.AdmActivity") and androguard.activity("app.six.CardAtivity") and androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED"))  
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
rule Android_Tordow_a
{
	meta:
		description = "Trojan-Banker.AndroidOS.Tordow."
		source = "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/"
	strings:
		$dropperA = {41 50 49 32 53 65 72 76 69 63 65}
		$dropperB = {64 69 32 2F 74 77 6F}
		$dropperC = {43 72 79 70 74 6F 55 74 69 6C}
		$droppedA = {72 61 63 63 6F 6F 6E}
		$droppedB = {50 52 49 56 41 54 45 5F 43 41 43 48 45}
		$droppedC = {63 6F 6E 74 65 6E 74 3A 2F 2F 73 6D 73 2F}
		$droppedD = {53 6D 73 4F 62 73 65 72 76 65 72}
	condition:
		( $dropperA and $dropperB and $dropperC ) or
		( $droppedA and $droppedB and $droppedC and $droppedD )
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
rule VideoTestNoicon_a
{
    meta:
        description = "Rule to catch APKs with app name VideoTestNoicon"
    condition:
        androguard.app_name(/VideoTestNoicon/i)
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
rule trojan_a: pornClicker
{
	meta:
		description = "Ruleset to detect android pornclicker trojan, connects to a remote host and obtains javascript and a list from urls generated, leading to porn in the end."
		sample = "5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca"
		reference = "https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/?utm_source=facebook&utm_medium=social"
	strings:
		$a = "SELEN3333"
		$b = "SELEN33"
		$c = "SELEN333"
		$api = "http://mayis24.4tubetv.xyz/dmr/ya"
	condition:
		($a and $b and $c and $api) or androguard.url(/mayis24\.4tubetv\.xyz/)
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
rule koodous_daaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
   strings:
       $serialVersionUID_Pattern = /Static\x20fields\x20{5}-\n(.+\n)+\x20{6}name\x20{10}:\x20'serialVersionUID'\n(.+\n)+\x20{6}value\x20{9}:\x20(0x0FC14E688B5377|0x09D8D10157142AE|0x37214C0A1F2548FF|0x559DB3549F77E491|-0x7014E03F2146082D|-0x0A537930CCB2EDD0)/
   condition:
       $serialVersionUID_Pattern  
}
rule koodous_eaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
 strings:
       $omegaSpyActivitiesPattern = /E:\x20activity\x20\(.+?\)\s+?A:\x20android:label.+?\s+?A:\x20android:name\([\dx]+?\)=("com\.android\.system\.MyLogin.+?"|"com\.android\.system\.AboutActivity"|"com\.android\.system\.HomeActitvity"|"com\.android\.system\.CreateAccountActivity"|"com\.android\.system\.MainActivity"|"com\.android\.system\.Splash"|"com\.android\.system\.Terms"|"com\.android\.system\.ConfigureActivity"|"com\.ispyoo\.common\..+?")/
   condition:
       $omegaSpyActivitiesPattern
}
rule DexClassLoader_b
{
	meta:
		description = "Ldalvik/system/DexClassLoader;"
	strings:
		$a = "Ldalvik/system/DexClassLoader;"
	condition:
		$a 
}
rule qihoo360_b: packer
{
	meta:
		description = "Qihoo 360"
	strings:
		$a = "libprotectClass.so"
	condition:
		$a 
}
rule ijiami_b: packer
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
rule naga_b: packer
{
	meta:
		description = "Naga"
	strings:
		$lib = "libddog.so"
	condition:
		 $lib
}
rule alibaba_b: packer
{
	meta:
		description = "Alibaba"
	strings:
		$lib = "libmobisec.so"
	condition:
		 $lib
}
rule baidu_b: packer
{
	meta:
		description = "Baidu"
	strings:
		$lib = "libbaiduprotect.so"
		$encrypted = "baiduprotect1.jar"
	condition:
		$lib or $encrypted
}
rule pangxie_b: packer
{
	meta:
		description = "PangXie"
	strings:
		$lib = "libnsecure.so"
	condition:
	 	$lib
}
rule Tencent_a
{
	meta:
		description = "Tencent"
    strings:
		$tencent_1 = "TxAppEntry"
		$tencent_2 = "StubShell"
		$tencent_3 = "com.tencent.StubShell.ProxyShell"
		$tencent_4 = "com.tencent.StubShell.ShellHelper"
	condition:
        any of them 
}
rule Ijiami_a
{
	meta:
		description = "Ijiami"
    strings:
		$1jiami_1 = "assets/ijiami.dat"
		$1jiami_2 = "ijiami.ajm"
		$1jiami_3 = "assets/ijm_lib/"
		$1jiami_4 = "libexecmain.so"
		$1jiami_5 = "libexec.so"
		$1jiami_6 = "rmeabi/libexecmain.so"
		$1jiami_7 = "neo.proxy.DistributeReceiver"
	condition:
        any of them 
}
rule Naga_a
{
	meta:
		description = "Naga"
    strings:
		$naga_1 = "libddog.so"
	condition:
        any of them 
}
rule Nagapt_a
{
	meta:
		description = "Nagapt (chaosvmp)"
    strings:
		$nagapt_1 = "chaosvmp"
		$nagapt_2 = "ChaosvmpService"
	condition:
        any of them 
}
rule Alibaba_a
{
	meta:
		description = "Alibaba"
    strings:
		$ali_1 = "libmobisec.so"
		$ali_2 = "libmobisecy1.zip"
		$ali_3 = "mobisecenhance"
		$ali_4 = "StubApplication"
	condition:
        any of them 
}
rule Baidu_a
{
	meta:
		description = "Baidu"
    strings:
		$baidu_1 = "libbaiduprotect.so"
		$baidu_2 = "baiduprotect1.jar"
		$baidu_3 = "baiduprotect.jar"
		$baidu_4= "libbaiduprotect_x86.so"
		$baidu_5 = "com.baidu.protect.StubApplication"
		$baidu_6 = "com.baidu.protect.StubProvider"
		$baidu_7 = "com.baidu.protect.A"
		$baidu_8 = "libbaiduprotect"
	condition:
        any of them 
}
rule Apkprotect_a
{
	meta:
		description = "Apkprotect"
    strings:
		$apkprotect_1 = ".apk@"
    	$apkprotect_2 = "libAPKProtect"
		$apkprotect_3 = "APKMainAPP"
	condition:
         ($apkprotect_1 and $apkprotect_2) or $apkprotect_3
}
rule PangXie_a
{
	meta:
		description = "PangXie"
    strings:
		$pangxie_1 = "libnsecure.so"
	condition:
        any of them 
}
rule LIAPP_a
{
	meta:
		description = "LIAPP"
    strings:
		$liapp_1 = "LiappClassLoader"
		$liapp_2 = "LIAPPEgg"
		$liapp_3 = "LIAPPClient"
		$liapp_4 = "LIAPPEgg.dex"
	condition:
        any of them 
}
rule Fake_Flash_Player_a
{
  meta:
       description = "Detects fake flashplayer apps"
	strings:
		$string_1 = "lock"
		$string_2 = "pay"
   condition:
	 $string_1 and $string_2 and
       (androguard.package_name(/com\.adobe\.flash/i) or androguard.app_name(/Adobe Flash/i)) 
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
rule CopyCatRule_a: official
{
	meta:
		description = "This rule detects the copycat malware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "mostatus.net"
		$b = "mobisummer.com"
		$c = "clickmsummer.com"
		$d = "hummercenter.com"
		$e = "tracksummer.com"
	condition:
		androguard.url("mostatus.net") or androguard.url("mobisummer.com") or
		androguard.url("clickmsummer.com") or androguard.url("hummercenter.com") or
		androguard.url("tracksummer.com")
		or $a or $b or $c or $d or $e
}
rule psserviceonline_a: urlbased
{
	meta:
		description = "This rule detects APKs that contat a well-known malware infection source 						https://blog.checkpoint.com/2015/09/21/braintest-a-new-level-of-sophistication-in-mobile-malware/"
		sample = "422fec2e201600bb2ea3140951563f8c6fbd4f8279a04a164aca5e8e753c40e8"
	strings:
		$malicious_url = "psserviceonline.com"
		$malicious_url_2 = "psservicedl.com"
		$malicious_url_3 = "himobilephone.com"
		$malicious_url_4 = "adsuperiorstore.com"
		$malicious_url_5 = "i4vip"
	condition:
		any of them 
		or androguard.url(/psserviceonline\.com/) or 
		cuckoo.network.dns_lookup(/psserviceonline\.com/) or 
		androguard.url(/psservicedl\.com/) or 
		cuckoo.network.dns_lookup(/psservicedl\.com/)
}
rule androrat_a
 {  
     meta:  
         description = “This malware is a bot that allows sms hook, calls and other information”  
         source = “Source from which we extracted the information, if not own”  
         author = “asanchez@koodous.com”  
     strings:  
         $activity = “AndroratActivity.java”  
         $classPath = “my/app/client/AndroratActivity”  
         $method = “Androrat.Client.storage”  
     condition:  
         all of them  
 }
rule slempo_b: package
{
	meta:
		description = "This rule detects the slempo (slembunk) variant malwares by using package name and app name comparison"
		sample = "24c95bbafaccc6faa3813e9b7f28facba7445d64a9aa759d0a1f87aa252e8345"
	condition:
		androguard.package_name("org.slempo.service")
		}
rule slempo_c
{
	meta:
			description = "SLEMPO"
	strings:
			$a = "#INTERCEPTED_SMS_START"
			$b = "#INTERCEPTED_SMS_STAR" 
			$c = "#block_numbers" 
			$d = "#wipe_data"
	condition:
			all of them
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
rule HiddenApp_a {
	strings:
	  	$ = /ssd3000.top/
		$ = "com.app.htmljavajets.ABKYkDEkBd"
	condition:
		1 of them
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
rule TriadaDetector_a
{
	meta:
		description = "Detect Triada"
	strings:
		$a = "VF*D^W@#FGF"
		$b ="export LD_LIBRARY_PATH"
	condition:
		$a or $b
}
rule DetectOverlayMaleware_a
{
	meta:
		description = "This rule detects the many overlays"
	strings:
		$a = ".Telephony.SMS_RECEIVED"
		$b = ".SYSTEM_ALERT_WINDOW"
		$c = "DEVICE_ADMIN_ENABLED"
		$d = "DEVICE_ADMIN_DISABLE_REQUESTED"
        $e = "ACTION_DEVICE_ADMIN_DISABLE_REQUESTED"
		$f = ".wakeup"
		$g = "device_admin"
	condition:
		$a and $b and $c and $d and $e and $f and $g
}
rule InjectionService_a
{
	meta:
		description = "This rule detects samples with possible malicious injection service"
		sample = "711f83ad0772ea2360eb77ae87b3bc45"
	condition:
		androguard.service(/injectionService/)
}
rule Marcher_a: AlarmAction
{
	meta:
		description = "This rule detects marcher new versions"
		sample = "c20318ac7331110e13206cdea2e7e2d1a7f3b250004c256b49a83cc1aa02d233"
		author = "DMA"
	condition:
		androguard.filter(/p\d{3}\w\.AlarmAction/)
}
rule BadAccents_a: ccm
{
        meta:
        description = "This rule was produced by CreateYaraRule and CommonCode, it detects badAccents malware"
        author = "_hugo_gonzalez_ "
		samples = "1e82fefd6b2c6f9a3f10d414180459d1067601ba16facd4a1aaff6921078015f"
        strings :
		$S_7_54_34 = { 54 20 03 00 71 10 ?? 00 00 00 0c 00 12 01 46 01 03 01 71 10 45 00 01 00 0a 01 6e 20 07 00 10 00 0e 00 }
		$S_7_22_116 = { 22 00 ?? 00 1a 01 ?? 00 70 20 0a 00 10 00 22 01 ?? 00 22 02 ?? 00 71 00 0f 00 00 00 0c 03 6e 10 3b 00 03 00 0c 03 71 10 4d 00 03 00 0c 03 70 20 4f 00 32 00 1a 03 02 00 6e 20 51 00 32 00 0c 02 6e 10 52 00 02 00 0c 02 70 20 39 00 21 00 71 10 0c 00 01 00 0c 01 1a 02 ?? 00 6e 30 0b 00 10 02 6e 20 31 00 04 00 0e 00 0d 01 28 fe 0d 01 28 fc 0d 01 28 fa }
		$S_7_22_274 = { 22 0b ?? 00 12 0c 46 0c 14 0c 70 20 53 00 cb 00 6e 10 54 00 0b 00 0c 02 6e 10 56 00 02 00 6e 10 57 00 02 00 0a 07 22 06 ?? 00 6e 10 55 00 0b 00 0c 0c 13 0d 00 28 70 30 38 00 c6 0d 22 08 ?? 00 22 0c ?? 00 71 00 0f 00 00 00 0c 0d 6e 10 3b 00 0d 00 0c 0d 71 10 4d 00 0d 00 0c 0d 70 20 4f 00 dc 00 1a 0d 02 00 6e 20 51 00 dc 00 0c 0c 6e 10 52 00 0c 00 0c 0c 70 20 3c 00 c8 00 13 0c 00 04 23 c4 ?? 00 16 09 00 00 6e 20 3e 00 46 00 0a 03 12 fc 33 c3 0d 00 6e 10 40 00 08 00 6e 10 3f 00 08 00 6e 10 3d 00 06 00 12 0c 11 0c 81 3c bb c9 12 1c 23 cc ?? 00 12 0d 22 0e ?? 00 70 10 4e 00 0e 00 16 0f 64 00 bd 9f 81 70 05 11 00 00 9e 0f 0f 11 84 ff 6e 20 50 00 fe 00 0c 0e 6e 10 52 00 0e 00 0c 0e 4d 0e 0c 0d 08 00 13 00 6e 20 20 00 c0 00 12 0c 6e 40 41 00 48 3c 28 c7 0d 05 1a 0c ?? 00 6e 10 44 00 05 00 0c 0d 71 20 10 00 dc 00 28 cc }
		$S_7_12_346 = { 12 05 12 14 54 61 02 00 71 10 ?? 00 01 00 0c 01 6e 20 11 00 51 00 22 00 ?? 00 22 01 ?? 00 71 00 0f 00 00 00 0c 02 6e 10 3b 00 02 00 0c 02 71 10 4d 00 02 00 0c 02 70 20 4f 00 21 00 1a 02 02 00 6e 20 51 00 21 00 0c 01 6e 10 52 00 01 00 0c 01 70 20 39 00 10 00 54 61 02 00 6e 10 ?? 00 01 00 0c 01 1a 02 ?? 00 6e 20 48 00 21 00 0a 01 38 01 10 00 54 61 02 00 6e 10 ?? 00 01 00 0c 01 1a 02 ?? 00 6e 20 48 00 21 00 0a 01 39 01 1a 00 6e 10 3a 00 00 00 0a 01 38 01 4f 00 22 01 ?? 00 54 62 02 00 70 20 17 00 21 00 23 42 ?? 00 71 00 ?? 00 00 00 0c 03 4d 03 02 05 6e 20 1a 00 21 00 54 61 02 00 6e 10 ?? 00 01 00 0c 01 1a 02 ?? 00 6e 20 48 00 21 00 0a 01 38 01 11 00 54 61 02 00 6e 10 ?? 00 01 00 0c 01 1a 02 ?? 00 71 30 13 00 21 04 0c 01 6e 10 14 00 01 00 54 61 02 00 6e 10 ?? 00 01 00 0c 01 1a 02 ?? 00 6e 20 48 00 21 00 0a 01 38 01 11 00 54 61 02 00 6e 10 ?? 00 01 00 0c 01 1a 02 ?? 00 71 30 13 00 21 04 0c 01 6e 10 14 00 01 00 0e 00 22 01 ?? 00 54 62 02 00 70 20 17 00 21 00 23 42 ?? 00 71 00 ?? 00 00 00 0c 03 4d 03 02 05 6e 20 1a 00 21 00 28 b3 }
		$S_7_6f_60 = { 6f 20 01 00 32 00 15 00 03 7f 6e 20 2f 00 02 00 14 00 01 00 05 7f 6e 20 ?? 00 02 00 0c 00 1f 00 ?? 00 5b 20 04 00 54 20 04 00 22 01 ?? 00 70 20 15 00 21 00 6e 20 12 00 10 00 0e 00 }
		$S_7_12_116 = { 12 02 2b 04 33 00 00 00 12 00 11 00 22 00 ?? 00 70 20 02 00 30 00 5b 30 08 00 54 30 08 00 1a 01 ?? 00 6e 20 06 00 10 00 54 30 08 00 6e 20 04 00 20 00 54 30 08 00 13 01 64 00 6e 20 05 00 10 00 54 30 08 00 12 11 6e 20 08 00 10 00 54 30 08 00 6e 20 03 00 20 00 54 30 08 00 6e 10 09 00 00 00 54 30 08 00 28 d3 00 00 00 01 01 00 00 00 00 00 05 00 00 00 }
		$S_7_54_56 = { 54 30 03 00 12 01 6e 20 ?? 00 10 00 54 30 03 00 6e 10 ?? 00 00 00 0c 00 1a 01 ?? 00 12 12 71 30 13 00 10 02 0c 00 6e 10 14 00 00 00 54 30 03 00 6e 10 ?? 00 00 00 0e 00 }
    condition:
        all of them
}
rule simplerule_a
{
	meta:
		description = "This rule detects a SMS Fraud malware"
	condition:
		androguard.package_name("com.hsgame.")
}
rule badaccents_a
{
	meta:
		description = "This rule detects badaccents"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.activity(/Badaccents/i) 
}
rule Mazain_a: bankbot
{
	meta:
		description = "This rule detects BankBot"
		hash_0 = "62ca7b73563f946df01d65447694874c45d432583f265fad11b8645903b6b099"
		hash_1 = "3bf02ae481375452b34a6bd1cdc9777cabe28a5e7979e3c0bdaab5026dd8231d"
		hash_2 = "6b93f837286da072f1ec7d5f5e049491d76d4d6ecc1784e1fadc1b29f4853a13"
		hash_3 = "d8b28dbcc9b0856c1b7aa79efae7ad292071c4f459c591de38d695e5788264d1"
		hash_4 = "bd194432a12c35ae6ae8a82fa18f9ecac3eb6e90c5ff8330d20d19e85a782958"
		hash_5 = "e0da58da1884d22cc4f6dfdc2e1da6c6bfe2b90194b86f57f9fc01b411abe8de"
		author = "Bâkır EMRE <bakir mail >"
	strings:
		$ = "/inj/"
		$ = "activity_inj"
		$ = /tuk/
		$ = /cmdlin/
	condition:
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and
		3 of them
		androguard.package_name("com.system.adobe.FlashPlayer") and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.url(/koodous\.com/) and
		file.sha256("62ca7b73563f946df01d65447694874c45d432583f265fad11b8645903b6b099") or
		file.sha256("3bf02ae481375452b34a6bd1cdc9777cabe28a5e7979e3c0bdaab5026dd8231d") or
		file.sha256("62ca7b73563f946df01d65447694874c45d432583f265fad11b8645903b6b099") or
		file.sha256("d8b28dbcc9b0856c1b7aa79efae7ad292071c4f459c591de38d695e5788264d1") or
		file.sha256("e0da58da1884d22cc4f6dfdc2e1da6c6bfe2b90194b86f57f9fc01b411abe8de") or	
}
rule Mazain_b: Banker
{
	meta:
		description = "This rule detects BankBot"
		hash_0 = "62ca7b73563f946df01d65447694874c45d432583f265fad11b8645903b6b099"
		hash_1 = "3bf02ae481375452b34a6bd1cdc9777cabe28a5e7979e3c0bdaab5026dd8231d"
		hash_2 = "6b93f837286da072f1ec7d5f5e049491d76d4d6ecc1784e1fadc1b29f4853a13"
		hash_3 = "d8b28dbcc9b0856c1b7aa79efae7ad292071c4f459c591de38d695e5788264d1"
		hash_4 = "bd194432a12c35ae6ae8a82fa18f9ecac3eb6e90c5ff8330d20d19e85a782958"
		hash_5 = "e0da58da1884d22cc4f6dfdc2e1da6c6bfe2b90194b86f57f9fc01b411abe8de"
		author = "Bâkır EMRE <bakir mail >"
	strings:
		$ = "ifc3yb3rs3cur1tych0.pw"
		$ = "1nj3ct10n.gdn "
		$ = "r0n4ld4.gdn"
		$ = "t4l1sc4.gdn"
		$ = "trolitrader.pw"
		$ = "bigbustown.pw"
		$ = "n0309.gdn"
		$ = "tr4f0.pw"
		$ = "t1lk1.gdn"
		$ = "b46.gdn"
	condition:
		all of ($string_*) and
		or androguard.package_name("com.system.adobe.FlashPlayer")
}
rule ransomware_c
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
rule SMS_Skunk_a
{
	condition:
		androguard.package_name(/org.skunk/) and
		androguard.permission(/SEND_SMS/)
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
rule Feecode_a: Payment
{
	condition:
		cuckoo.network.dns_lookup(/viapayplugdl\.feecode\.cn/) and
		not androguard.app_name("\xe8\xa5\xbf\xe7\x93\x9c\xe6\x88\x90\xe4\xba\xba\xe7\x89\x88") // xi gua cheng ren ban
}
rule PaPaVideo_a
{   
	meta:
		sha256 = "e6e362a100906988a68b322e28874d8234a03c1147b5bab8fb80867db3ce08a5"
	condition:
		cuckoo.network.dns_lookup(/tyuio\.127878\.com/) or
		cuckoo.network.dns_lookup(/www\.ayroe\.pw/)
}
rule MeiHuoVideo_a
{
	meta:
		sha256 = "452b79e21757af4c38735845b70a143fdbdef21c9e5b7a829f7a670192fbda8f"
	condition:
		cuckoo.network.dns_lookup(/app\.97aita\.com/) or
		cuckoo.network.dns_lookup(/sx\.ifanhao\.cc/) or 
		cuckoo.network.dns_lookup(/qubo\.kandou\.cc/) or 
		cuckoo.network.dns_lookup(/imgtu\.chnhtp\.com/)
}
rule Dowgin_a: URL
{
	meta:
		description = "This rule detects Dowgin Related Samples by network traffic keywords, like cd.ld.clspw.cn/app/20160518/201605181740719.apk"
		sample = ""
	condition:
		androguard.url(/cd.ld.clspw.cn/) or
		cuckoo.network.http_request(/cd.ld.clspw.cn/) or
		androguard.url(/td.tt.0312ttt.com/) or
		cuckoo.network.http_request(/td.tt.0312ttt.com/) or
		androguard.url(/dc.ie.027ie.com/) or
		cuckoo.network.http_request(/dc.ie.027ie.com/) or
		androguard.url(/dm.bd.52hm.net/) or
		cuckoo.network.http_request(/dm.bd.52hm.net/) or
		androguard.url(/ad.wd.daoudao.com/) or
		cuckoo.network.http_request(/ad.wd.daoudao.com/) or
		androguard.url(/d.n.150155.cn/) or
		cuckoo.network.http_request(/d.n.150155.cn/) or
		androguard.url(/apk.d.ad.139188.net/) or
		cuckoo.network.http_request(/apk.d.ad.139188.net/) or
		androguard.url(/zd.sd.0792zs.cn/) or
		cuckoo.network.http_request(/zd.sd.0792zs.cn/) or
		androguard.url(/dk.ma.app258.net/) or
		cuckoo.network.http_request(/dk.ma.app258.net/) or
		androguard.url(/101.36.100.86/) or
		cuckoo.network.http_request(/101.36.100.86/) or
		androguard.url(/cd.tv.cdstv.cn/) or
		cuckoo.network.http_request(/cd.tv.cdstv.cn/) or
		androguard.url(/apk.d.ad.180189.cn/) or
		cuckoo.network.http_request(/apk.d.ad.180189.cn/) or
		androguard.url(/nd.ed.netera.cn/) or
		cuckoo.network.http_request(/nd.ed.netera.cn/) or
		androguard.url(/vd.pd.vpvtv.cn/) or
		cuckoo.network.http_request(/vd.pd.vpvtv.cn/) or
		androguard.url(/cd.ld.clspw.cn/) or
		cuckoo.network.http_request(/cd.ld.clspw.cn/) or
		androguard.url(/apk.d.ad.yuanfenup.com/) or
		cuckoo.network.http_request(/apk.d.ad.yuanfenup.com/) or
		androguard.url(/apk.d.ad.youday.cn/) or
		cuckoo.network.http_request(/apk.d.ad.youday.cn/) or
		androguard.url(/td.od.56tools.cn/) or
		cuckoo.network.http_request(/td.od.56tools.cn/) or
		androguard.url(/ns.d.ad.dooudoo.com/) or
		cuckoo.network.http_request(/ns.d.ad.dooudoo.com/) or
		androguard.url(/dd.dy.0086dy.net/) or
		cuckoo.network.http_request(/dd.dy.0086dy.net/) or
		androguard.url(/ns.nd.youday.com.cn/) or
		cuckoo.network.http_request(/ns.nd.youday.com.cn/) or
		androguard.url(/ns.d.duod.cn/) or
		cuckoo.network.http_request(/ns.d.duod.cn/) or
		androguard.url(/d.ad.139199.com/) or
		cuckoo.network.http_request(/d.ad.139199.com/) or
		androguard.url(/dk.da.woai3g.net/) or
		cuckoo.network.http_request(/dk.da.woai3g.net/) or
		androguard.url(/s.d.133166.cn/) or
		cuckoo.network.http_request(/s.d.133166.cn/)
}
rule OtakuVideo_a: chinese_porn
{
	meta:
		sample = "449a9fc0694b483a4c1935b33eea433268560784d819f0d63bf66080f5529df8"
	condition:
		cuckoo.network.dns_lookup(/api\.hykuu\.com/) or
		cuckoo.network.dns_lookup(/wo\.ameqq\.com/) or
		cuckoo.network.dns_lookup(/home\.qidewang\.com/) or
		cuckoo.network.dns_lookup(/img\.gdhjkm\.com/)
}
rule Levida_a
{
	condition:
		androguard.url(/safe\-server\-click\.com/) or 
		cuckoo.network.dns_lookup(/safe\-server\-click\.com/)
}
rule Mmsk_a: Downloader
{
	meta:
		sha1 = "2c2d28649ba525f8b9ae8521f6c5cd0ba2f8bb88"
    condition:
		androguard.url(/911mmsk\.com/) or
		cuckoo.network.dns_lookup(/cdn\.angrydigital\.com/) or
		cuckoo.network.dns_lookup(/911mmsk\.com/) or
		cuckoo.network.http_request(/dws\.mobiappservice\.net:8080/) or
		cuckoo.network.http_request(/211.137.56.201\/videoplayer/) or
		cuckoo.network.http_request(/c\.91fuxin\.com/) or
		cuckoo.network.http_request(/cdn\.gahony\.com\/apk/) or
		cuckoo.network.http_request(/dl\.cline\.net\.cn/) or
		cuckoo.network.http_request(/jkl\.cjoysea\.com:8080/)
}
rule PimentoRoot_b: rootkit
{
	condition:
		androguard.url(/http:\/\/webserver\.onekeyrom\.com\/GetJson\.aspx/)
}
rule Clevernet_a: Adware
{
	condition:
		androguard.url(/clevernet/)
}
rule UrlDownloader_a: Downloader
{
	condition:
		androguard.url(/stat\.siza\.ru/) or 
		androguard.url(/4poki\.ru/) or 
		androguard.url(/dating\-club\.mobie\.in/) or 
		androguard.url(/systems\.keo\.su/)
}
rule koodous_faaaa: official
{
	meta:
		description = "This rule detects banking services phonenumbers hardcoded in apk"
	strings:
		$str15999999  =   "15999999"
		$str15991111  =   "15991111"
		$str15442100  =   "15442100"
		$str15882100  =   "15882100"
		$str80055550  =   "80055550"
		$str15881599  =   "15881599"
		$str15889999  =   "15889999"
		$str15448000  =   "15448000"
		$str15778000  =   "15778000"
		$str15998000  =   "15998000"
	condition:
		1 of them 
}
rule AiQingYingShi_a: chinese_porn
{
	condition:
	androguard.app_name(/\xe7\x88\xb1\xe6\x83\x85[\w]+?\xe5\xbd\xb1\xe8\xa7\x86[\w]{,11}/)  //273bcec861e915f39572a169ae98d4c2afae00800259c1fe5e28c075923d90ca
}
rule JinBoShiPin_a: chinese_porn
{
	condition:
		androguard.app_name("\xe7\xa6\x81\xe6\x92\xad\xe8\xa7\x86\xe9\xa2\x91") // jin bo shi pin 277b8320ceb8481a46198f7b9491aef5e9cf54ecda32ca419d0f1aaa422f34cd
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
rule koodous_gaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "Yeahmobi_Trackping"
	condition:
		all of them
}
rule cellspy_a: monitor
{
	meta:
		sample = "2b1b61cc6e0e291c53bce9db0e20b536d3c8371ce92cad5fc1dec4fa3f9d06c3"
	condition:
		androguard.url(/cellspy.mobi/) or
		cuckoo.network.dns_lookup(/cellspy\.mobi/)
}
rule luluvideo_a: chinese_porn
{
	meta:
		sample = "f243a64965619acc4523e8e738846a3983ad91650bd41ce463a3a3ff104ddfd1"
	condition:
		cuckoo.network.http_request(/www\.sexavyy\.com:8088/) or 
		cuckoo.network.http_request(/spimg\.ananyy\.com/)
}
rule PornPlayer_URL_a
{
	meta:
		description = "This rule detects PornPlayer by network traffic keywords, like /ckplayer/style.swf"
		sample = ""
		examples = "33vid.com/,	44ytyt.com/, 8765kkk.com/, avsss66.com/, avsss88.com/, ffcao11.com/media/ckplayer/"
	condition:
		androguard.url(/\/ckplayer\/style\.swf/) or
		cuckoo.network.http_request(/\/ckplayer\/style\.swf/)
}
rule clicksummer_a
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
rule koodous_haaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "HELLO"
		$b = "PONG"
		$c = "SLEEP"
		$d = "WAIT"
		$e = "CREATE"
		$f = "HELLO\n"
	condition:
		all of them
}
rule downloader_c
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
rule koodous_iaaaa: official
{
	meta:
		description = "This rule detects sample that mess around with the sensitive system/priv-app path (for payload dropping etc)"
	strings:
		$certs_path = "etc/security/cacerts"
	condition:
		$certs_path
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
rule TrustEVTracker_a
{
	meta:
		description = "This rule detects TransUnion TrustEV SDK"
	strings:
		$a = "https://app.trustev.com/api/v2.0/session"
	condition:
		$a  and
		androguard.permission(/android.permission.INTERNET/)
}
rule FinBoxINTracker_a
{
	meta:
		description = "This rule detects FinBox India SDK"
	strings:
		$a = "https://riskmanager.apis.finbox.in"
		$b = "https://api.finbox.in/api"
		$c = "https://logger.apis.finbox.in"		
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)
}
rule cloak_and_dagger_a: official
{
	meta:
		description = "Potential Cloak and Dagger attack - http://cloak-and-dagger.org"
	condition:
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
}
rule koodous_jaaaa: official
{
}
rule koodous_kaaaa: official
{
	meta:
		description = "Korea Phishing app"
	condition:
		androguard.package_name("sakura.phonetransfer")		
}
rule WhatsupTrojan_a
{
	meta:
		description = "This rule detects the WhatsupTrojan app based on different indicators"
		family = "WhatsupTrojan"
	condition:
		  (
			  androguard.permission(/REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
			  androguard.permission(/REQUEST_DELETE_PACKAGES/) and
			  androguard.permission(/SYSTEM_ALERT_WINDOW/) and
			  androguard.permission(/ACCESS_NETWORK_STATE/) and
			  androguard.permission(/WAKE_LOCK/) and
			  androguard.permission(/INTERNET/)
		  )
		  and
		  (
		  	  androguard.activity(/\.Asterisk$Act/) and
			  androguard.activity(/\.Consulate$RequestActivity/) and
			  androguard.activity(/\.CaptureData$AlertActivity/) and
			  androguard.activity(/\.CaptureData$WebViewActivity/) or
			  androguard.activity(/\.SUActivity/) or
			  androguard.activity(/\.ScreenOnAndUnlock/)
		  )
		  and
		  (
		  	  androguard.service(/AccService/i) and
			  androguard.service(/GeneralService/i) and
			  androguard.service(/RegisterReceiverService/i) and
			  androguard.service(/Operation/i)
		  )
}
rule newdress_a: official
{		 
		meta:
		description = "This rule detects Dresscode samples"
        strings:
                $a = /const-string v[0-9]?[0-9]?, "SVOOL"/
                $b = "wun03_mrxhn_mvg"
                $c = /const-string v[0-9]?[0-9]?, "XIVZGV"/
                $d = /const-string v[0-9]?[0-9]?, "KRMT"/
                $e = /const-string v[0-9]?[0-9]?, "HOVVK"/
                $f = /const-string v[0-9]?[0-9]?, "DZRG"/
                $g = /const-string v[0-9]?[0-9]?, "KLMT"/
        condition:
                $a or $b or $c or $d or $e or $f or $g
}
rule fake_wallet_apps_a: official
{
	meta:
		description = "Detect fake wallet apps"
		sample = "f8c0f2d6cfd09c398465cfb913628f9dceaa850b49a2c9022dad7be0f931e81e"
		sample = "e81c3278f46f480ea3c0dda21b2781700ca438c6a4287d4746ba527134c6e71e"
	condition:
		androguard.permission(/android.permission.INTERNET/) and
		androguard.url(/coinwalletinc\.com/)
}
rule coinimp_basic_a: official
{
	meta:
		description = "Basic rule to detect CoinImp apps - see https://www.coinimp.com/documentation"
	strings:
		$coinimp = "https://www.hostingcloud.racing/7rry.js"
	condition:
		androguard.permission(/android.permission.INTERNET/) and
		$coinimp
}
rule sauronlocker_android_app_a
{
    meta:
        description = "Sauron Locker"
        package_name = "com.ins.screensaver"
        sample = "a145ca02d3d0a0846a6dde235db9520d97efa65f7215e7cc134e6fcaf7a10ca8,09192d3095b7708378d4578d5c331cda7b9125d406b63d55b6855f774bbfc41f"
    strings:
        $str1 = "attach.php?uid="
        $str2 = "&os="
        $str3 = "&model="
        $str4 = "&permissions=0&country="
        $str5 = "encrypted"
        $url1 = "http://timei2260.myjino.ru"
        $url2 = "http://d91976z0.beget.tech"
    condition:
        androguard.package_name("com.ins.screensaver") and
        androguard.permission(/android.permission.SET_WALLPAPER/) and
        androguard.service(/com.ins.screensaver.services.CheckerService/) and
        (all of ($str*)) or (1 of ($url*))
}
rule FRSLabsSDKTracker_a
{
	meta:
		description = "All FRSLabs SDK Apps"
	condition:
		androguard.activity("com.frslabs.android.sdk.scanid.activities.IDScannerActivity") or
		androguard.activity("com.frslabs.android.sdk.facesdk.activities.FaceCaptureActivity") or
		androguard.activity("com.frslabs.android.sdk.videosdk.ui.WorkflowActivity")
}
rule KhoslaVideoeKYCTracker_a
{
	meta:
		description = "All Khosla Video eKYC SDK Apps"	
	condition:		
		androguard.activity("com.khoslalabs.videoidkyc.ui.init.VideoIdKycInitActivity")
}
rule Android_Trojan_FakeAd_A_a
{  
	meta:
		description = "Rule used to detect Jio and PayTM fakeapp"
		source = "Lastline"
		Author = "Anand Singh"
		Date = "04/12/2019"
	strings:
		$a1 = "bhadva.chromva.jio" wide
		$a2 = ".jio4goffers." wide
		$b1 = "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE" wide
		$b2 = {2E 00 6A 00 69 00 6F 00 ?? 00 67 00 6F 00 66 00 66 00 65 00 72 00 73 00 00 00} //j.i.o.?.g.o.f.f.e.r.s
		$b3 ={00 6A 00 69 00 6F 00 ?? 00 6F 00 66 00 66 00 65 00 72 00 73 00 00}
		$c1 = "android.permission.READ_CONTACTS" wide
		$c2 = "android.permission.READ_SMS" wide
		$c3 = "android.permission.READ_EXTERNAL_STORAGE" wide
		$c4 = "android.permission.WRITE_EXTERNAL_STORAGE" wide
		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}
	condition:
		$hexstr_targetSdkVersion and ((any of ($a*) or (any of ($b*)) and 3 of ($c*)))
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
rule mopub_b: adware
{
	meta:
		description = "This rule detects apks thats connects to http://www.mopub.com/ adware company - not reference for malware"
		sample = "273ea61d4aea7cd77e5c5910ce3627529428d84c802d30b8f9d6c8d227b324c1"
	condition:
		cuckoo.network.dns_lookup(/ads\.mopub\.com/)
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
rule parse_a
{
	meta:
		description = "This rule detects aplicactions relationship with http://parse.com/"
		sample = ""
	condition:
		cuckoo.network.dns_lookup(/api\.parse\.com/)
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
rule DroidJack_a
{
	meta:
		description = "Detects only the ones that weren't obfuscated. Such as the samples like the repackaged Pokemon Go APK"
		family = "DroidJack"
	strings:
		$a = "droidjack"
		$b = "incoming_number"
	condition:
		($a and $b)
}
rule packers_c: Ijiami
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
rule packers_d: qihoo
{
	meta:
		description = "This rule detects packers based on files used by them"
		description2 = "This is for an old version, new versions use 360 and qihoo activities"
	strings:
		$qihoo_1 = "monster.dex"
    	$qihoo_2 = "libprotectClass"
	condition:
		2 of them
}
rule packers_e: bangcle
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
rule packers_f: ali
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$ali_1 = "libmobisecy.so"
		$ali_2 = "libmobisecy1.zip"
	condition:
		any of them
}
rule packers_g: liapp
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$liapp_1 = "LIAPPEgg.dex"
    	$liapp_2 = "LIAPPEgg"
	condition:
		2 of them
}
rule packers_h: tencent
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$tencent_1 = "libmain.so"
		$tencent_2 = "libshell.so"
	condition:
		2 of them
}
rule packers_i: i360
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$i360_1 = "libjiagu.so"
		$i360_2 = "libjiagu_art.so"
	condition:
		2 of them
}
rule packers_j: baidu
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
rule packers_k
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$bangcle_1 = "libsecmain.so"
		$bangcle_2 = "libsecexe.so"
		$i360_1 = "libjiagu.so"
		$i360_2 = "libjiagu_art.so"
		$ali_1 = "libmobisecy.so"
		$ali_2 = "libmobisecy1.zip"
		$baidu_1 = "libbaiduprotect.so"
		$baidu_2 = "baiduprotect.jar"
		$baidu_3= "libbaiduprotect_x86.so"
		$tencent_1 = "libmain.so"
		$tencent_2 = "libshell.so"
		$qihoo_1 = "monster.dex"
    	$qihoo_2 = "/libprotectClass"
		$liapp_1 = "LIAPPEgg.dex"
    	$liapp_2 = "/LIAPPEgg"
		$apkprotect_1 = ".apk@"
    	$apkprotect_1 = "/libAPKProtect"
	condition:
		2 of them
}
rule ransomware_d: from_cromosome
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
rule shuanet_a: from_cromosome
{
	meta:
		description = "This rule detects shuanet aggresive malware"
		sample = "created with the help of cromosome.py"
	strings:
		$a = "android.permission.ACCESS_FINE_LOCATION"
		$b = "Lcom/freshui/dextamper/MainActivity"
		$c = "android.permission.RECEIVE_BOOT_COMPLETED"
		$d = "Lorp/frame/shuanet/abs/DataReciver"
		$e = "SHA1-Digest: vYhWz0BWI6qxF2Yy/kAhIUaP5M8="
		$f = "/tmp/ndk-user/tmp/build-stlport/ndk/sources/cxx-stl/gabi++/src/dynamic_cast.cc"
		$g = "com.boyaa.push.NotifyCenter"
		$h = "libcrypt.so"
	condition:
		all of them
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
rule koodous_laaaa: official
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
rule Godless_a
{
	meta: 
		description = "This rule detects the AndroidOS.Godless Auto-Rooting Trojan"
	strings:
		$a = "KEY_REUEST_TEMP_ROOT"
		$c = "downloadUrl"
	condition:
		($a and $c)
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
rule non_named_a
{
	meta:
	description = "This rule detects something"
	strings:
		$a = "SHA1-Digest: D1KOexBGmlpJS53iK7KjJcyzt7o="
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
rule qihoo360_c: packer
{
	meta:
		description = "Qihoo 360"
	strings:
		$a = "libprotectClass.so"
	condition:
		$a 
}
rule ijiami_c: packer
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
rule naga_c: packer
{
	meta:
		description = "Naga"
	strings:
		$lib = "libddog.so"
	condition:
		 $lib
}
rule alibaba_c: packer
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
rule baidu_c: packer
{
	meta:
		description = "Baidu"
	strings:
		$lib = "libbaiduprotect.so"
		$encrypted = "baiduprotect1.jar"
	condition:
		$lib or $encrypted
}
rule pangxie_c: packer
{
	meta:
		description = "PangXie"
	strings:
		$lib = "libnsecure.so"
	condition:
	 	$lib
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
rule koodous_maaaa: official
{
	strings:
		$droidplugin = "droidplugin"
	condition:
		$droidplugin
}
rule koodous_naaaa: official
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
rule koodous_oaaaa: official
{
	meta:
		description = "This rule detects a string that appears in droidplugin/core/PluginProcessManager"
		sample_based_on = "49ff608d2bdcbc8127302256dc7b92b12ea9449eb96255f9ab4d1da1a0405a1b"
	strings:
		$message_str = "preMakeApplication FAIL"
	condition:
		$message_str
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
rule test2_a
{
	meta:
		description = "This rule detects apps with VirusService"
		sample = "5C0A65D3AE9F45C9829FDF216C6E7A75AD33627A"
	condition:
		androguard.service(/\.VirusService/i)
}

rule HackingTeam_Android_a: Android Implant
{
	meta:
		description = "HackingTeam Android implant, known to detect version v4 - v7"
		author = "Tim 'diff' Strazzere <strazz@gmail.com>"
                reference = "http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/"
		date = "2016-11-14"
		version = "1.0"
        strings:
        $decryptor = {  12 01               // const/4 v1, 0x0
                        D8 00 ?? ??         // add-int/lit8 ??, ??, ??
                        6E 10 ?? ?? ?? 00   // invoke-virtual {??} -> String.toCharArray()
                        0C 04               // move-result-object v4
                        21 45               // array-length v5, v4
                        01 02               // move v2, v0
                        01 10               // move v0, v1
                        32 50 11 00         // if-eq v0, v5, 0xb
                        49 03 04 00         // aget-char v3, v4, v0
                        DD 06 02 5F         // and-int/lit8 v6, v2, 0x5f <- potentially change the hardcoded xor bit to ??
                        B7 36               // xor-int/2addr v6, v3
                        D8 03 02 ??         // and-int/lit8 v3, v2, ??
                        D8 02 00 01         // and-int/lit8 v2, v0, 0x1
                        8E 66               // int-to-char v6, v6
                        50 06 04 00         // aput-char v6, v4, v0
                        01 20               // move v0, v2
                        01 32               // move v2, v3
                        28 F0               // goto 0xa
                        71 30 ?? ?? 14 05   // invoke-static {v4, v1, v5}, ?? -> String.valueOf()
                        0C 00               // move-result-object v0
                        6E 10 ?? ?? 00 00   // invoke-virtual {v0} ?? -> String.intern()
                        0C 00               // move-result-object v0
                        11 00               // return-object v0
                     }
        $settings = {
                        00 24 4C 63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 6E
                        64 72 6F 69 64 2F 67 6C 6F 62 61 6C 2F 53 65 74
                        74 69 6E 67 73 3B 00
                    }
        $getSmsInputNumbers = {
                                00 12 67 65 74 53 6D 73 49 6E 70 75 74 4E 75 6D
                                62 65 72 73 00
                              }
      condition:
        $decryptor and ($settings and $getSmsInputNumbers)
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
rule banking_b
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
rule marcher2_b
{
	strings:
		$a = "HDNRQ2gOlm"
		$b = "lElvyohc9Y1X+nzVUEjW8W3SbUA"
	condition:
		all of them
}
rule marcher3_b
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
rule koodous_paaaa: official
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
rule clicker_b: url
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
rule Igexin_a
{
	meta:
		description = "igexin"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_a = "android.intent.action.GTDOWNLOAD_WAKEUP"
	condition:
		any of ($strings_*)
}
rule leadbolt_b: advertising
{
	meta:
		description = "Leadbolt"
	condition:
		androguard.url(/http:\/\/ad.leadbolt.net/)
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
rule fbilocker_a_a
{
	meta:
		description = "FBILocker.A"
	strings:
		$a = "74F6FD5001ED11E4A9DEFABADE999F7A"
	condition:
		$a
}
rule Rana_Android_resources_a {
strings:
        $res1 = "res/raw/cng.cn" fullword wide ascii
        $res2 = "res/raw/att.cn" fullword wide ascii
        $res3 = "res/raw/odr.od" fullword wide ascii
condition:
        any of them
}
rule FakeCoC_a
{
	meta:
		description = "This rule detects fake Clash of Clans apps"
	strings:
		$url = "cliphot.me"
	condition:
		(androguard.app_name("Clash of Clans") and androguard.permission(/SEND_SMS/)) or
		$url
}
rule sushinow_a
{
    strings:
        $launcher_image = "EA DB A8 44 25 9A 27 93 8A 25 D2 E0 A2 42 8B D6 F8 10 11 F2 C4 5D 10 D2 8B FA D5 8C DC 5E 85 FA F5 E3 90 9F 23 1B DB BE 45 AC B2 86 0D 19 33 CB 5F 1F A9 0A 45 A3 40 E4 AC 3C 58 58 7D A6 F7 DB B9 00 20 A4 8D 82 B3 60 3A EA 4E 32 43 DB B7 8A A9 3E 8E 58 58 22 05 88 6C 9F 2F 7A 24 91 CC B1 2A 40 CE 82 19 F1 6B 2B 3F 18 66 B4 4E 4E 74 FB 56 31 49 24 73 B6 CF 17 3D 91 42 14 31 40 E3 8B C8 4F AD 3C 0F 15 B3 27 C6 B1 AD 49 5D BF 87 9C 9C E8 F6 AD 64 AA AF E3 06 10 59 70 BF E0 74 48 64 9E 95 01 E2 9C F9 F1 6B CB 55 D8 ED EF BA 93 2C E1 ED 5B C9 1C 12 99 B7 E0 7E C1 19 09 44 11 01 74 CB 95 DC 95 48 26 63 D4 F0 F6 AD 06 91 EA"
        $app_id = "013df7ae-6c39-4a9e-9151-fd626d536dcc"
        $app_server = "EhUbWAcbLRoGAD5FHQAJ"
    condition:
        $launcher_image or $app_id or $app_server
}
rule music_player_apk_a
{
meta:
	description = "rule to uniquely identify apk"
strings:
	$a = ".field public static final ic_launcher_music:I = 0x7f050006"
	$b = ".field public static final ic_launcher_music_jooxy:I = 0x7f050007"
	$c = ".method public constructor <init>(Ljava/util/List;Lokhttp3/internal/connection/StreamAllocation;Lokhttp3/internal/http/HttpCodec;Lokhttp3/internal/connection/RealConnection;ILokhttp3/Request;Lokhttp3/Call;Lokhttp3/EventListener;III)V"
	$d = ".method public constructor <init>(Lokhttp3/ConnectionPool;Lokhttp3/Address;Lokhttp3/Call;Lokhttp3/EventListener;Ljava/lang/Object;)V"
	$e = ".method public constructor <init>(Lokhttp3/Address;Lokhttp3/internal/connection/RouteDatabase;Lokhttp3/Call;Lokhttp3/EventListener;)V"
	$f = ".method public constructor <init>(Lokhttp3/Request;Lokhttp3/WebSocketListener;Ljava/util/Random;J)V"
	$g = ".method constructor <init>(Lokhttp3/EventListener;)V"
	$h = ".method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;Landroid/location/LocationManager;Landroid/location/LocationListener;)V"
	$i = "com.securicy.bubblewrapgame"
condition:
	$a and $b and $c and $d and $e and $f and $g and $h and $i
}
rule security_a: Google Chrome
{
	meta:
		info = "This rule will detect a Trojan banker"
		sha="36004af3567c2f09b108dbc30458507f38ed2e2a6f462213b5f5cd783adacc7a"
		sample_name = "Chrome"
	strings:
		$a = "tjnahlcl.tdpk.kdkl"
		$b = "iwncbde.ixkpw.jjucczi"
		$c = "ebsn.ejnaa.clswqsrq"
	condition:
		all of them
}
rule Minecraft_b
{
	meta:
		description = "A rule to detect malicious Minecraft APKS. Minecraft should not do anything with SMSes and should not need phone information such as boot completed. It should also not do https requests and access elemnts of the page."
		sample = "35bb105bd203c0677466d2e26e71a28ba106f09db3a7b995e796825f5f0e1908"
	strings:
		$js_class = /getElement(sByClassName | ByID )/
		$click = "click()"
	condition:
		androguard.app_name(/Minecraft/) and (
		$js_class or $click or
		androguard.url("https://api.onesignal.com/") or
		androguard.permissions(/android.permission.READ_SMS/) or
		androguard.permissions(/android.permission.SEND_SMS/) or
		androguard.permissions(/android.permission.RECEIVE_SMS/) or
		androguard.permissions(/android.permission.WRITE_SMS/) or
		androguard.permissions(/android.permission.RECEIVE_BOOT_COMPLETED/) or
		androguard.permissions(/android.permission.READ_PHONE_STATE/) or
		androguard.permissions(/android.permission.USER_PRESENT/) or
		androguard.activity(/\.sms\./)
		)
}
rule Trojan_f: Obscuro Banking Trojan
{
	meta:
        description = "Trojan targeting Banks with Overlays"
		source = "https://securelist.com/ghimob-tetrade-threat-mobile-devices/99228/"
	strings:
		$c2_1 = "AppSealingService"
		$c2_2 = "AppSealingIPService"
		$c2_3 = "AccessibilityService"
		$c2_4 = "xmlpull"
	condition:
		2 of ($c2_*)
		and (
			androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/) 
			or androguard.permission(/android.permission.FOREGROUND_SERVICE/)) or
		androguard.certificate.sha1("E7BA28ECA0760524411B2D2476BDAE65C274B46A") or
		androguard.certificate.sha1("6DB41284B29ADF5FCFFFB3712D827161E26B504A") or
		androguard.certificate.sha1("E5029BA773B141CDD9C7352EA5BC63275B975303") or
		androguard.certificate.sha1("3BA519FBDDF5CB33203DC55255FA589FF4B0F983")
}
rule koodous_qaaaa: official
{
	meta:
		description = "This rule detects the Fresh cleaner application, a Trojan 							used to gain backdoor access"
		sample = "c0403093672b782d2a95fe5cf5ce8bc4"
		reference = 
		"https://koodous.com/apks/abd99e70679da305251c8d2c38b4364b9c919a88aa144cd0e5ea65fdf598d664"
	strings:
		$a = "http://ELB-API-127-1069859428.ap-southeast-1.elb.amazonaws.com/in"
	condition:
		androguard.package_name("com.fresh.cleaner") and
		androguard.app_name("Fresh Cleaner") and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.PACKAGE_USAGE_STATS/)   
		and $a 
}
rule SimpLocker_a
{
	meta:
		description = "SimpLocker"
		sample = "fd694cf5ca1dd4967ad6e8c67241114c"
		reference = "http://kharon.gforge.inria.fr/dataset/malware_SimpLocker.html"
	strings:
		$a = "http://example.com/"
		$b = "http://xeyocsu7fu2vjhxs.onion/"
		$c = "https://check.torproject.org"
	condition:
	all of them 
}
rule TractorSMS_a
{
	meta:
		description = "Detects tractor-apps that send and receive SMS"
	strings:
		$a = "const-string v3, u'sms_body'"
		$b = "const-string v0, u'sms_body'"
		$c = "http://10.0.0.172"
	condition:
		$a and $b and $c and androguard.app_name("com.safetest.tractor")
}
rule NoobHost_a
{
	meta:
		Author= "Anna and Felicia"
		email = "s1958410@vuw.leidenuniv.nl"
		reference= "https://koodous.com/apks/c1a3e1a372df344b138e2edb541fdc1d7c1842726ca85a38137ca902a0e5dc6b"
		sample = "c1a3e1a372df344b138e2edb541fdc1d7c1842726ca85a38137ca902a0e5dc6b"
		date = "03/11/2020"
		description = "This is a basic YARA rule for CEO fraud."
	strings:
		$a = "_mips.so"
		$b = "jiagu"
		$c = "jiagu_x86"
		$d = "mips"
		$e = "_a64.so"
		$f = "https://t.me/POLICEryn2"
	condition:
		($a or $b or $c or $d or $e or $f) or
		androguard.package_name("noob.yt.team") or
	  	androguard.certificate.sha1("66ebe8f6a719790a2194c34b1f1bfb8df344f870")
}
rule Anubis_Variant_a: BankBot
{
	meta:
        description = "Anubis malware targeting banks"
		source = ""
	strings:
		$c2_1 = "/o1o/a6.php" nocase
		$c2_2 = "/o1o/a14.php" nocase
		$c2_3 = "/o1o/a3.php" nocase
	condition:
		2 of ($c2_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
			or androguard.permission(/android.permission.SEND_SMS/)
		)
}
rule smsfraud_c
{
	meta:
		sample = "7ea9a489080fa667b90fb454b86589ac8b018c310699169b615aabd5a0f066a8"
		search = "cert:14872DA007AA49E5A17BE6827FD1EB5AC6B52795"
	condition:
		androguard.certificate.sha1("14872DA007AA49E5A17BE6827FD1EB5AC6B52795")
}
rule smsfraud2_a {
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
rule packers_l: apkprotect
{
	meta:
		description = "This rule detects packers based on files used by them"
	strings:
		$apkprotect_1 = ".apk@"
    	$apkprotect_2 = "libAPKProtect"
	condition:
		2 of them
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
rule gazon_a
{
	meta:
		description = "This rule detects gazon adware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "ads-184927387.jar"
	condition:
		$a
}
rule shuanet_b: adWare
{
	meta:
		description = "This rule detects shuanet aggresive malware"
	condition:
		androguard.service(/com\/boyaa\/push/) and
		androguard.receiver(/orp\/frame\/shuanet\/abs/)
}
rule shuanet2_a: adWare
{
	meta:
		description = "This rule detects shuanet aggresive malware"
	condition:
		androguard.service("com/boyaa/push/NotifyCenterAIDL") and
		androguard.receiver("orp/frame/shuanet/abs/DataReciver")
}
rule koodous_raaaa: official
{
	meta:
		description = "identify samples that check if root"
	strings:
		$isroot = "uid=0"
	condition:
		$isroot
}
rule SMSPay_b
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
rule koodous_saaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$pass = "MyDifficultPassw"
		$exec = "EncExc"
	condition:
		$pass and $exec
}
rule Acecard_b
{
	meta:
		description = "This rule detects acecard families"
		sample = "3c0a9db3f1df04e23c5b8bd711402570a370474853df2541ef187b9997721bc3"
	strings:
		$a = "app_bin/iptables"
		$b = "app_bin/tor"
		$c = "/proc/cpuinfo"
		$d = "ServiceStarter"
		$e = "SDCardServiceStarter"
        $f = "MyDeviceAdminReceiver"
        $g = "MessageReceiver"
		$h = "USSDService"
	condition:
		androguard.filter("android.intent.action.ACTION_EXTERNAL_APPLICATIONS_AVAILABLE") and
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and 
		5 of them
}
rule koodous_taaaa: official
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
rule AfricanScamware_a
{
	meta:
		description = "Detects scamware originating from Africa"
		family = "AfricanScamware"
	strings:
		$a = "http://5.79.65.207:8810"
		$b = "http://plus.google.com"
	condition:
		($a and $b)
}

rule Android_Triada_b: android
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
rule citrusRAT_a {
	meta:
		description = "Ruleset to detect an Italian RAT." 
		sample = "f26658419a9113b0b79ecd58966aee93deec77ea713ff37af36c249002419310" 
	strings:
		$a = "/system/bin/screenrecord /sdcard/example.mp4"
		$b = "/system/bin/rm /sdcard/img.png"
		$c = "2.117.118.97"
		$d = "monitorSMSAttivo"
		$f = "+393482877835"
		$g = "fin qui OK 7"
		$h = "/system/xbin/"
	condition:
		all of them 
}
rule koodous_uaaaa: official
{
	meta:
		description = "Adware showing full-screen ads even if infected app is closed"
		sample = "0e18c6a21c33ecb88b2d77f70ea53b5e23567c4b7894df0c00e70f262b46ff9c"
		ref_link = "http://news.drweb.com/show/?i=10115&c=38&lng=en&p=0"
	condition:
		androguard.receiver(/com\.nativemob\.client\.NativeEventReceiver/)
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
rule koodous_vaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "com.loki.sdk.ILokiListene"
	condition:
		any of them
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
rule SpyNet_a
{
	meta:
		description = "Ruleset to detect SpyNetV2 samples. "
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
	$a = "odNotice.txt"
	$b = "camera This device has camera!"
	$c = "camera This device has Nooo camera!"
	$d = "send|1sBdBBbbBBF|K|"
	$e = "send|372|ScreamSMS|senssd"
	$f = "send|5ms5gs5annc"
	$g = "send|45CLCLCa01"
	$h = "send|999SAnd|TimeStart"
	$i = "!s!c!r!e!a!m!"
	condition:
		4 of them 
}
rule DroidRt_a
{
	meta:
		sample = "f50dc3592737532bc12ef4954cb2d7aeb725f6c5eace363c8ab8535707b614b3"
	condition:
		cuckoo.network.dns_lookup(/download\.moborobo\.com/)
}
rule SMSReg_a
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
rule jmede_a
{
	meta:
		description = "http://blog.avlsec.com/2016/07/3381/pokemon-go/"
	condition:
		cuckoo.network.dns_lookup(/if\.anycell\-report\.com/) or
		cuckoo.network.dns_lookup(/if\.jmede\.com/) or
		cuckoo.network.dns_lookup(/down\.tuohuangu\.com/)
}
rule OmniRat_a: Certs
{
    condition:
        androguard.certificate.sha1("B17BACFB294A2ADDC976FE5B8290AC27F31EB540")
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
rule fakeav_cert_a
{
	meta:
		description = "fakeav msg premium"
		sample = ""
	condition:
		androguard.certificate.sha1("1C414E5C054136863B5C460F99869B5B21D528FC")
}
rule fakeav_url_a
{
	meta:
		description = "fakeav msg premium"
		sample = ""
	condition:
		androguard.url(/topfiless\.com\/rates\.php/) 
}
rule AdultAdware_a: official
{
	meta:
		description = "This rule detects the variant from https://blogs.mcafee.com/mcafee-labs/sex-sells-looking-at-android-adult-adware-apps/"
		sample = "BB2E56B9259D945592D7A6DDDBCEDCF82DDF3E5A52232377B5648AAACC3F12FB"
	strings:
		$a = {26 41 64 73 43 6F 75 6E 74 3D}
		$b = {26 48 6F 75 72 53 69 6E 63 65 49 6E 73 74 61 6C 6C 3D}
		$c = {26 4F 72 69 49 50 3D}
		$d = {43 4F 4E 56}
		$e = {4C 6F 61 64 6F 66 66 65 72}
		$f = {58 58 41 44 53 43 4F 55 4E 54}
	condition:
		$a and $b and $c and $d and $e and $f  
}
rule koodous_waaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "libhooker.so"
	condition:
		any of them
}
rule guiasitio_a: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.url(/guiasitio\.com.*/)
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
rule koodous_xaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = /.*espectapatronum.*/
	condition:
		any of them
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
rule koodous_yaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "ActivityManager$RunningTaskInfo;->topActivity"
	condition:
		any of them
}
rule koodous_zaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "getRunningForegroundApps"
	condition:
		any of them
}
rule fakeGames_a
{
	meta:
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		google_play = "https://play.google.com/store/apps/developer?id=Dawerominza"
	strings:
		$a = "http://ggd.prnlivem.com/frerr.php"
		$b = "Lcom/gte/fds/j/a;"
	condition:
		any of them
}
rule adware_e
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
rule smsreg_a
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
rule facebook_b: fakebook
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
rule redalert2_b
{
	meta:
		author = "R"
		description = "https://clientsidedetection.com/new_android_trojan_targeting_over_60_banks_and_social_apps.html"
	strings:
		$intent = "HANDLE_COMMANDS"
	condition:
		$intent
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
rule Momo_a
{
	condition:
		androguard.package_name("com.mobo.gram") and
		androguard.activity(/StepTwoActivityForce/i)
}
rule Exobotv2_a: abc
{
	meta:
		description = "Exobot payload abc"
		sample = "a04dee90bbd98cae515c0084acbd18aa91f1de6db28a415c0ac8688286f0acd3"
	condition:
		androguard.permissions_number == 20 and
		androguard.permission(/ACCESS_FINE_LOCATION/) and	
		androguard.permission(/ACCESS_NETWORK_STATE/) and
		androguard.permission(/CALL_PHONE/) and
		androguard.permission(/GET_TASKS/) and	
		androguard.permission(/INTERNET/) and
		androguard.permission(/PACKAGE_USAGE_STATS/) and
		androguard.permission(/READ_CONTACTS/) and
		androguard.permission(/READ_EXTERNAL_STORAGE/) and
		androguard.permission(/READ_PHONE_STATE/) and
		androguard.permission(/READ_SMS/) and
		androguard.permission(/RECEIVE_BOOT_COMPLETED/) and	
		androguard.permission(/RECEIVE_SMS/) and
		androguard.permission(/RECORD_AUDIO/) and
		androguard.permission(/REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
		androguard.permission(/SEND_SMS/) and
		androguard.permission(/SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/WAKE_LOCK/) and
		androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/WRITE_SMS/)
}
rule Anubis_c
{
	meta:
    	description = "Rule set for detect Anubis banker"
    	sample = "0ce93cabedaccdc9c2f4752df7359002e3735e772afd48d94689aff80bcb7685"
    strings:
        $string_1= "ad"
        $string_2= "dL"
        $string_3= "ik"
        $string_4= "el"
        $string_5= "yS"
        $string_6= "ub"
        $string_7= "ta"
        $string_8= "us"
        $string_24= "po"
        $string_32= "si"
        $string_40= "ti"
        $string_48= "ve"
        $string_64= "al"
        $string_72= "ue"
        $string_88= "in"
        $string_104= "ap"
        $string_112= "ac"
        $string_120= "it"
    condition:
         all of ($string_*) and
         androguard.filter("com.htc.intent.action.QUICKBOOT_POWERON") and
         androguard.permissions_number == 19 and
         androguard.permission(/ACCESS_FINE_LOCATION/) and
         androguard.permission(/SEND_SMS/) and
         androguard.permission(/READ_EXTERNAL_STORAGE/) and
         androguard.permission(/RECEIVE_BOOT_COMPLETED/) and
         androguard.permission(/REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
         androguard.permission(/READ_CONTACTS/) and
         androguard.permission(/READ_PHONE_STATE/) and
         androguard.permission(/SYSTEM_ALERT_WINDOW/) and
         androguard.permission(/WRITE_SMS/) and
         androguard.permission(/ACCESS_NETWORK_STATE/) and
         androguard.permission(/RECORD_AUDIO/) and
         androguard.permission(/WAKE_LOCK/) and
         androguard.permission(/GET_TASKS/) and
         androguard.permission(/CALL_PHONE/) and
         androguard.permission(/RECEIVE_SMS/) and
         androguard.permission(/INTERNET/) and
         androguard.permission(/PACKAGE_USAGE_STATS/) and
         androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
         androguard.permission(/READ_SMS/)
}
rule GhostTeam_a
{
	meta:
		description = "This rule will be able to tag all GhostTeam samples"
		hash_1 = "efca498b6a6715337cdedf627690217cef2d80d1c8f715b5c37652f556134f7e"
		hash_2 = "f3223010d0beace2445561bcb62ffaa491423cad0b94ca0c811a8e165b9b94a8"
		hash_3 = "f6feabac83250af4fe4eeaea508bf35da329c97d5f0c1a4b87c483f80ea40d50"
		reference_1 = "https://blog.trendmicro.com/trendlabs-security-intelligence/ghostteam-adware-can-steal-facebook-credentials/"
		reference_2 = "https://blog.avast.com/downloaders-on-google-play-spreading-malware-to-steal-facebook-login-details"
		author = "Jacob Soo Lead Re"
		date = "07-August-2018"
	condition:
		androguard.receiver(/.ScreenR/i)
		and androguard.receiver(/.BS/i) 
		and androguard.receiver(/.SR/i)
		and androguard.service(/.FS/i)
		and androguard.service(/.LS/i)
		and androguard.service(/.SO/i)
		and androguard.filter(/android.intent.action.BOOT_COMPLETED/i)
}
rule Crymore_a
{
	meta:
		description = "Cryptocurrency Miner, Crymore"
		packageName = ""
		link1 = "https://drive.google.com/uc?authuser=0&id=183OvtemBaJiP_dPkdCHpcNTjBeTqtP_C&export=download"
		link2 = "https://raw.githubusercontent.com/cryptominesetting/setting/master/Config"
		link3 = "https://raw.githubusercontent.com/cryptominesetting/setting/master/Config2"
		link4 = "https://drive.google.com/uc?authuser=0&id=1nfl9nCCeWkG071NWeOm6fGl8QPvvrtpp&export=download"
	strings:
		$a_1 = {68747470733a2f2f64726976652e676f6f676c652e636f6d2f75633f61757468757365723d302669643d3138334f7674656d42614a69505f64506b64434870634e546a4265547174505f43266578706f72743d646f776e6c6f6164}
		$a_2 = {68747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f63727970746f6d696e6573657474696e672f73657474696e672f6d61737465722f436f6e666967}
		$a_3 = {68747470733a2f2f64726976652e676f6f676c652e636f6d2f75633f61757468757365723d302669643d316e666c396e434365576b473037314e57654f6d3666476c385150767672747070266578706f72743d646f776e6c6f6164}
	condition:
		any of ($a*)
}
rule koodous_baaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$ = "QD_SUBID"
		$ = "ASt20180731"
		$ = "bHgSwitch"
		$ = "HeguSDK"
		$ = "sviptodo"
		$ = "android.intent.ss.rbcm"
		$ = "adv.google-global.com"
		$ = "moast.zip"
		$ = "android.intent.start.dta"
		$ = "instance_taskcontainer"
		$ = "android.intent.action.stopsp"
		$ = "aHR0cHM6Ly9hcGkubml1bW9iaS5jb20vYWEvbmM="
		$ = "api.jsian.com"
	condition:
		any of them or
		androguard.url(/google-global.com/) or
		androguard.url("198.11.177.209") or
		androguard.url("47.254.56.0") or
		androguard.url("47.88.10.168") or
		androguard.url(/adv.gmscenter.org/) or
		androguard.url(/adv.google-global.com/) or
		androguard.url(/api.jsian.com/) or
		androguard.url(/rcv.ilabtap.com/) or
		cuckoo.network.dns_lookup(/google-global.com/) or
		cuckoo.network.dns_lookup(/adv.gmscenter.org/) or
		cuckoo.network.dns_lookup(/jsian.com/)
}
rule koodous_caaaaa: official
{
	meta:
		description = "Obfuscation going on"
	strings:
		$yes_1 = "obfuscate" nocase
		$yes_2 = "obfuscation" nocase
		$yes_3 = "obfuscated" nocase
		$yes_4 = "deobfuscat" nocase
		$no1 = "obfuscatedIdentifier" nocase
		$no2 = "com.android.vending.licensing.AESObfuscator-1" nocase
		$no3 = "ObfuscatedCall"
		$no4 = "ObfuscatedCallP"
		$no5 = "ObfuscatedCallRet"
		$no6 = "ObfuscatedCallRetP"
		$no7 = "ObfuscatedFunc"
		$no8 = "ObfuscatedAddress"
		$no9 = "LVLObfusca"
	condition:
		any of ($yes_*) and not any of ($no*)
}
rule avdobfuscator_a: obfuscator
{
  meta:
    description = "AVDobfuscator"
    url         = "https://github.com/andrivet/ADVobfuscator"
  strings:
    $o1 = "ObfuscatedAddress"
    $o3 = "ObfuscatedCall"
    $o4 = "ObfuscatedCallP"
    $o5 = "ObfuscatedCallRet"
    $o6 = "ObfuscatedCallRetP"
    $o7 = "ObfuscatedFunc"
  condition:
    1 of ($o*) //and $elf_magic at 0
}
rule HeroBot_a
{
	meta:
		description = "This rule will be able to tag all HeroBot samples"
		refernces = "https://www.welivesecurity.com/2018/06/18/new-telegram-abusing-android-rat/"
		hash_1 = "3b40b5081c2326f70e44245db9986f7a2f07a04c9956d27b198b6fc0ae51b3a2"
		hash_2 = "a002fca557e33559db6f1d5133325e372dd5689e44422297406e8337461e1548"
		hash_3 = "92edbf20549bad64202654bc51cc581f706a31bd8d877812b842d96406c835a1"
		author = "Jacob Soo Lead Re"
		date = "21-June-2018"
	condition:
		androguard.activity(/OS\.Cam/i)
		and androguard.activity(/OS\.MainActivity/i) 
		and androguard.service(/OS\.mainservice/i)
		and androguard.service(/OS\.voiceservice/i)
		and androguard.receiver(/OS\.smsreceiver/i) 
		and androguard.receiver(/OS\.callreceiver/i) 
		and androguard.receiver(/OS\.booton/i)
}
rule koodous_daaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$ = "downloader_center_instance"
		$ = "ww_proj"
		$ = "1fa78cfb99fbdb144751ccd9a086e65e"
		$ = "f3c744d950bf70dfc8c7cbcae23f26fa"
		$ = "ck2@13!4"
	condition:
		any of them
		or cuckoo.network.dns_lookup(/xuenya.net/)
		or cuckoo.network.dns_lookup(/os-1253691939.file.myqcloud.com/)
		or androguard.url(/os-1253691939.file.myqcloud.com/)		
}
rule koodous_eaaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		url = " https://www.yangzhi968.com/20171112/du2.html?source=1"
	condition:
		androguard.package_name(/com.abel.abel/) or
		androguard.package_name(/com.ansun.IosFirstfang/) or
		androguard.package_name(/com.ansun.IosV2/) or
		androguard.package_name(/com.ansun.IosV2qp/) or
		androguard.package_name(/com.ansun.firstfang/) or
		androguard.package_name(/com.ansun.firstfangFr/) or
		androguard.package_name(/com.ansun.v2/) or
		androguard.package_name(/com.ansun.v2Fr/) or
		androguard.package_name(/com.app8412.IosIebbs/) or
		androguard.package_name(/com.app8412.LobbyGame/) or
		androguard.package_name(/com.app8412.SinBaGame/) or
		androguard.package_name(/com.app8412.iebbs/) or
		androguard.package_name(/com.app8412.iebbsFr/) or
		androguard.package_name(/com.bingo.IosBingo/) or
		androguard.package_name(/com.bingo.bingo/) or
		androguard.package_name(/com.bingo.bingoFr/) or
		androguard.package_name(/com.chester.NF0043/) or
		androguard.package_name(/com.chester.NF0043Fr/) or
		androguard.package_name(/com.chuxuan.chuxuan/) or
		androguard.package_name(/com.chuxuan.chuxuanFr/) or
		androguard.package_name(/com.duniang.IosDuniang/) or
		androguard.package_name(/com.duniang.IosDuniang2/) or
		androguard.package_name(/com.duniang.duniang/) or
		androguard.package_name(/com.duniang.duniangFr/) or
		androguard.package_name(/com.fd0371.AllFun/) or
		androguard.package_name(/com.fd0371.AllFun5Fr/) or
		androguard.package_name(/com.fd0371.AllFunFr/) or
		androguard.package_name(/com.fd0371.IceGame/) or
		androguard.package_name(/com.fd0371.IceGame9/) or
		androguard.package_name(/com.fd0371.IceGameFr/) or
		androguard.package_name(/com.fengniao.fengniao/) or
		androguard.package_name(/com.fengniao.fengniaoFr/) or
		androguard.package_name(/com.fuhao.IosFlbhqy/) or
		androguard.package_name(/com.fuhao.IosHqy/) or
		androguard.package_name(/com.fuhao.IosHqy3/) or
		androguard.package_name(/com.fuhao.flbhqy/) or
		androguard.package_name(/com.fuhao.flbhqyFr/) or
		androguard.package_name(/com.fuhao.hqy/) or
		androguard.package_name(/com.fuhao.hqyFr/) or
		androguard.package_name(/com.handui1026.LobbyGame/) or
		androguard.package_name(/com.haoyun.IosLucky/) or
		androguard.package_name(/com.haoyun.lucky/) or
		androguard.package_name(/com.haoyunqipai.haoyunqipai/) or
		androguard.package_name(/com.haoyunqipai.haoyunqipaiFr/) or
		androguard.package_name(/com.hch029.IosLobby/) or
		androguard.package_name(/com.hch029.LobbyDebug/) or
		androguard.package_name(/com.hch029.LobbyGame/) or
		androguard.package_name(/com.hch029.QLLobbyGame/) or
		androguard.package_name(/com.hiapps.HiappsBluePeak/) or
		androguard.package_name(/com.hiapps.HiappsDuniang/) or
		androguard.package_name(/com.hiapps.HiappsEagle/) or
		androguard.package_name(/com.hiapps.HiappsPaiquFr/) or
		androguard.package_name(/com.hiapps.HiappsTianyun/) or
		androguard.package_name(/com.hiapps.HiappsWinasking/) or
		androguard.package_name(/com.hiapps.HiappsYixiu/) or
		androguard.package_name(/com.hongyun.IosWinAsKing/) or
		androguard.package_name(/com.hongyun.WinAsKing/) or
		androguard.package_name(/com.hongyun.WinAsKingFr/) or
		androguard.package_name(/com.ianetest.dandanzhuan/) or
		androguard.package_name(/com.jinzun123.jinzun123/) or
		androguard.package_name(/com.jinzun123.jinzun123Fr/) or
		androguard.package_name(/com.jixiuqinga.jixiuqinga/) or
		androguard.package_name(/com.jixiuqinga.jixiuqingaFr/) or
		androguard.package_name(/com.jjqp.IosJiujiu/) or
		androguard.package_name(/com.jjqp.jiujiu/) or
		androguard.package_name(/com.jjqp.jiujiuFr/) or
		androguard.package_name(/com.juying.IosEagle/) or
		androguard.package_name(/com.juying.eagle/) or
		androguard.package_name(/com.juying.eagleFr/) or
		androguard.package_name(/com.jxqp.IosJixiang/) or
		androguard.package_name(/com.jxqp.jixiang/) or
		androguard.package_name(/com.jxqp.jixiangFr/) or
		androguard.package_name(/com.landing.IosBluePeak/) or
		androguard.package_name(/com.landing.blue_peak/) or
		androguard.package_name(/com.landing.blue_peak4/) or
		androguard.package_name(/com.landing.blue_peak40$/) or
		androguard.package_name(/com.landing.bluepeakFr/) or
		androguard.package_name(/com.leg1077.LobbyGame/) or
		androguard.package_name(/com.paiqu.IosPaiqu/) or
		androguard.package_name(/com.pearq12.LobbyGame/) or
		androguard.package_name(/com.qbqp.Ios7bao/) or
		androguard.package_name(/com.qbqp.Ios7baoFr/) or
		androguard.package_name(/com.qbqp.qibao/) or
		androguard.package_name(/com.qbqp.qibaoFr/) or
		androguard.package_name(/com.qbqp.qibao_001/) or
		androguard.package_name(/com.qyqp.IosQuying/) or
		androguard.package_name(/com.qyqp.quying/) or
		androguard.package_name(/com.qyqp.quyingFr/) or
		androguard.package_name(/com.sbxgame.IosLobbyGameFr/) or
		androguard.package_name(/com.sbxgame.LobbyDebug/) or
		androguard.package_name(/com.sbxgame.LobbyDemo/) or
		androguard.package_name(/com.sbxgame.LobbyGame/) or
		androguard.package_name(/com.sbxgame.LobbyGame0Fr/) or
		androguard.package_name(/com.sbxgame.LobbyGameFr/) or
		androguard.package_name(/com.soso.soso/) or
		androguard.package_name(/com.soso.sosoFr/) or
		androguard.package_name(/com.taizi.IosTz/) or
		androguard.package_name(/com.taizi.tz/) or
		androguard.package_name(/com.taizi.tzFr/) or
		androguard.package_name(/com.thai.TestSkin/) or
		androguard.package_name(/com.tianyun.IosHonor/) or
		androguard.package_name(/com.tianyun.IosHonor2/) or
		androguard.package_name(/com.tianyun.honor/) or
		androguard.package_name(/com.tianyun.liluo/) or
		androguard.package_name(/com.u9.IosPostive/) or
		androguard.package_name(/com.u9.positive02/) or
		androguard.package_name(/com.u9.postive/) or
		androguard.package_name(/com.u9.postiveFr/) or
		androguard.package_name(/com.unionasone.IosYixiu/) or
		androguard.package_name(/com.unionasone.yixiu/) or
		androguard.package_name(/com.unionasone.yixiuFr/) or
		androguard.package_name(/com.vip2002.vip2002/) or
		androguard.package_name(/com.vip2002.vip2002Fr/) or
		androguard.package_name(/com.wangzhe.cnty/) or
		androguard.package_name(/com.wangzhe.cntyFr/) or
		androguard.package_name(/com.wangzhe.thekingdom/) or
		androguard.package_name(/com.wangzhe.thekingdomFr/) or
		cuckoo.network.http_request(/\/route\/test/) or
		cuckoo.network.http_request(/\/service\/conf\/init?t=/)
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
rule APT_Loader_a
{
	meta:
		description = "This rule will be able to tag this particular loader samples"
		hash_1 = "8f062f35fd838b00b6cfc3e7df3adedfe710e5f205f48e280e75a885d474b29b"
		Reference = "https://twitter.com/ThreatFabric/status/1020619670565597184"
		author = "Jacob Soo Lead Re"
		date = "16-July-2018"
	condition:
		androguard.activity(/AdminActivity/) and
		androguard.activity(/MainActivity/) and
		androguard.service(/AdminService/) and
		androguard.service(/MainService/) and
		androguard.receiver(/AdminReceiver/) and
		androguard.receiver(/MainReceiver/)
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
rule trojanSMS_b
{
	meta:
		description = "This rule detects trojan SMS"
		sample = "ff8ccead81eca2154cf9e891e15f52c8a154ea3aba5e62498b11fb843135837f"
		source = "http://pastebin.com/rLPux7ts"
	strings:
}
rule YaYaGene_a: rule1 {
	meta:
		author = "YaYaGen -- Yet Another Yara Rule Generator (*) v0.4_winter17/18"
		date = "03 Jan 2018"
		url = "https://koodous.com/apks?search=be44cc5f3ec413f649154a515725fff58fd87fb47fd83201577872c2594b7f84%20OR%20%209548ee4acd88262a084aba5bac2002746fff85ed83008c9cdf2a13199ab77aa6%20OR%20%20d70fa70efbff55eafc9077bc6ed49798d5cf966a2a0cb8062ff6ffb5c688773c%20OR%20%20014996cc63ed7ba6118149166290303df1dce4daaf27a194222746e9160dcfaa%20OR%20%20dc96d4230bb489acd3b823b22345626d0e0ac8ba48871f8fa864974ba504faec%20OR%20%2075759cc9af54e71ac79fbdc091e30b4a6e5d5862d2b1c0decfb83c9a3d99b01b%20OR%20%20ad03a820f5458977d1a8621c7a64722e08bf85acdbbca23bae345aa4e573a0eb%20OR%20%20621e6eb85c67f4af9eb5a3a5afee99f5a797d84cb606bb2bfc8d387517fb08ba%20OR%20%20b902c0cb656addf4fbd5c6b1836233445e9e1775944a0b0551e1e2d4cfd87372"
	condition:
		androguard.url("http://192.168.100.4:8101") or 
		(androguard.url("http://91.226.11.200") or 
		cuckoo.network.dns_lookup(/91\.226\.11\.200/)  or 
		cuckoo.network.http_request(/91\.226\.11\.200/)) or 
		androguard.url("http://91.226.11.200/pl/alior/index.html") or 
		androguard.url("http://91.226.11.200/pl/bzwbk/index.html") or 
		androguard.url("http://91.226.11.200/pl/ingbank/index.html") or 
		androguard.url("http://91.226.11.200/pl/mbank/index.html") or 
		androguard.url("http://91.226.11.200/pl/millennium/index.html") or 
		androguard.url("http://91.226.11.200/pl/pekao/index.html") or 
		androguard.url("http://91.226.11.200/pl/pkobp/index.html") or 
		androguard.url("http://91.226.11.200/pl/plusonline/index.html") or 
		androguard.url("http://91.226.11.200/pl/raiffeisen/index.html") or 
		androguard.url("http://91.226.11.200/pl/smartbank/index.html")
}
rule detection_c
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
rule android_coinhive_fake_hack_app_a {
  meta:
		description = "This rule detects Android Fake App, that uses Coinhive"
		author = "Corsin Camichel, @cocaman"
		version = "2018-01-07"
		in_the_wild = true
    tlp = "green"
  strings:
    $string_1 = "Jakaminen:"
    $string_2 = "Hack"
    $string_3 = "initialActivityCount"
  condition:
  	all of ($string_*)
}
rule GMS_a: jcarneiro
{
	meta:
		description = "This rule detects the usage of Google Mobile Services"
	strings:
		$a = "com.google.android.gms"
	condition:
		$a	
}
rule BANKBOT_a: malware
{
	meta:
		date = "2018-01-19"
	strings:
		$a = {2f 70 72 69 76 61 74 65 2f 74 75 6b 5f 74 75 6b 2e 70 68 70}
	condition:
		all of them
}
rule BANKBOT_VERSION_a: malware
{
	meta:
		date = "2018-01-18"
		sample = "40ad2444b83f6a1c25dd153214a1a16bcaa2640ebaf7735d6f1ee2591989e58e"
	strings:
		$a1 = {2f 70 72 69 76 61 74 65 2f 63 68 65 63 6b 50 61 6e 65 6c 2e 70 68 70}
		$a2 = {2f 70 72 69 76 61 74 65 2f 74 75 6b 5f 74 75 6b 2e 70 68 70}
	condition:
		all of them
}
rule ollvm_v3_4_a: obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.4"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "cd16ad33bf203dbaa9add803a7a0740e3727e8e60c316d33206230ae5b985f25"
  strings:
    $clang_version = "Obfuscator-clang version 3.4 "
    $based_on      = "(based on LLVM 3.4"
  condition:
    all of them
}
rule ollvm_v3_6_1_a: obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 3.6.1"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "d84b45856b5c95f7a6e96ab0461648f22ad29d1c34a8e85588dad3d89f829208"
  strings:
    $clang_version = "Obfuscator-LLVM clang version 3.6.1 "
    $based_on      = "(based on Obfuscator-LLVM 3.6.1)"
  condition:
    all of them
}
rule ollvm_v4_0_a: obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 4.0"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "aaba570388d0fe25df45480ecf894625be7affefaba24695d8c1528b974c00df"
  strings:
    $clang_version = "Obfuscator-LLVM clang version 4.0.1 "
    $based_on      = "(based on Obfuscator-LLVM 4.0.1)"
  condition:
    all of them
}
rule ollvm_v6_0_strenc_a: obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 6.0 (string encryption)"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = "f3a2e6c57def9a8b4730965dd66ca0f243689153139758c44718b8c5ef9c1d17"
  strings:
    $clang_version = "Obfuscator-LLVM clang version 6.0."
    $based_on      = "(based on Obfuscator-LLVM 6.0."
    $strenc        = /datadiv_decode[0-9]{18,20}/
  condition:
    all of them
}
rule ollvm_v6_0_a: obfuscator
{
  meta:
    description = "Obfuscator-LLVM version 6.0"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
    example     = ""
  strings:
    $clang_version = "Obfuscator-LLVM clang version 6.0."
    $based_on      = "(based on Obfuscator-LLVM 6.0."
  condition:
    all of them and not ollvm_v6_0_strenc
}
rule ollvm_a: obfuscator
{
  meta:
    description = "Obfuscator-LLVM version unknown"
    info        = "https://github.com/obfuscator-llvm/obfuscator/wiki"
  strings:
    $ollvm1 = "Obfuscator-LLVM "
    $ollvm2 = "Obfuscator-clang "
  condition:
    ($ollvm1 or $ollvm2) and
    not ollvm_v3_4 and
    not ollvm_v3_6_1 and
    not ollvm_v4_0 and
    not ollvm_v6_0 and
    not ollvm_v6_0_strenc
}
rule koodous_faaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}
	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("Koodous") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.INTERNET/) and
}
	strings:
		$dbhook = "SQLiteDatabaseHook"
		$message_str = "preMakeApplication FAIL"
	condition:
		all of them
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
rule koodous_gaaaaa: official
{
	meta:
		description = "This rule detects coinhive Apps"
	strings:
		$coinhive = "https://coinhive.com/lib/coinhive.min.js"
	condition:
		androguard.permission(/android.permission.INTERNET/) and
		$coinhive 
}
rule ANDROIDOS_JSMINER_a
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/coin-miner-mobile-malware-returns-hits-google-play/; 		https://twitter.com/LukasStefanko/status/925010737608712195"
		sample = "22581e7e76a09d404d093ab755888743b4c908518c47af66225e2da991d112f0"
	strings:
		$url = "coinhive.com/lib/coinhive.min.js"
		$s1 = "CoinHive.User"
		$s2 = "CoinHive.Anonymous"
	condition:
		$url and 1 of ($s*)	
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
rule newdress_b: official
{
	meta:
		description = "This rule detects the Dresscode"
	strings:
		$a = "wun03_mrxhn_mvg"
	condition:
		$a 
		}
rule koodous_haaaaa: SuspiciousBanker_C
{
	meta:
		description = "This rule detects sample based on device_Admin"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a1 = "android.app.action.DEVICE_ADMIN_ENABLED" wide
		$a2 = "android.permission.INTERNET" wide
		$a3 = "android.accessibilityservice.AccessibilityService" wide
		$b1 = "android.permission.READ_SMS" wide
		$b2 = "android.permission.SEND_SMS" wide
		$b3 = "android.permission.RECEIVE_SMS" wide
		$b4 = "android.permission.WRITE_SMS" wide
		$c1 = "android.permission.WRITE_EXTERNAL_STORAGE" wide
		$c2 = "android.permission.READ_EXTERNAL_STORAGE" wide
		$c3 = "android.permission.READ_PHONE_STATE" wide
		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}
	condition:
		2 of ($a*) and (3 of ($b*) or (2 of ($b*) and 2 of ($c*))) and $hexstr_targetSdkVersion and filesize < 180KB
}
rule koodous_iaaaaa: SuspiciousPermission_D
{
	meta:
		description = "Check Sample based on the suspicious permission"
		sample = ""
	strings:
$a1 = "android.permission.SYSTEM_ALERT_WINDOW" wide
		$a2 = "android.permission.INTERNET" wide
		$b1 = "android.permission.READ_SMS" wide
		$b2 = "android.permission.SEND_SMS" wide
		$b3 = "android.permission.RECEIVE_SMS" wide
		$b4 = "android.permission.WRITE_SMS" wide
		$c1 = "android.permission.WRITE_EXTERNAL_STORAGE" wide
		$c2 = "android.permission.READ_EXTERNAL_STORAGE" wide
		$c3 = "android.permission.READ_PHONE_STATE" wide
		$d1 = "android.permission.READ_CONTACTS" wide
		$d2 = "android.permission.WRITE_CONTACTS" wide
		$d3 = "android.permission.KILL_BACKGROUND_PROCESSES" wide
		$d4 = "com.android.launcher.permission.INSTALL_SHORTCUT" wide
		$e1 = "com.android.launcher.permission.UNINSTALL_SHORTCUT" wide
		$e2 = "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION" wide
		$e3 = "android.permission.SYSTEM_OVERLAY_WINDOW" wide
		$exclude1 = "com.stone.sdkcore.base" wide
		$exclude2 = "com.paypal.android.sdk" wide
		$exclude3 = "xiaomi" wide
		$exclude4 = "HOTLIST_FM_PUSH" wide
		$exclude5 = "mobilesafe" wide
		$exclude6 = ".samsung." wide
		$exclude7 = "com.facebook.sdk." wide
		$exclude8 = "GRANT_RUNTIME_PERMISSIONS" wide
		$exclude9 = "appstore.battery" wide
		$exclude10 = "com.google.android.c2dm.permission.RECEIVE" wide	
		$exclude11 = "accountsdk.auth" wide
		$exclude12 = "android.permission.WRITE_SECURE_SETTINGS" wide
		$exclude13 = "android.permission.UPDATE_DEVICE_STATS" wide
		$exclude14 ="android.settings.ADD_ACCOUNT_SETTINGS" wide
		$exclude15 ="android.permission.BLUETOOTH_ADMIN" wide
		$exclude16 ="com.google.android.gms.permission.ACTIVITY_RECOGNITION" wide
		$exclude17 ="com.baidu" wide
		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}
	condition:
		$hexstr_targetSdkVersion and not (any of ($exclude*)) and filesize < 40KB and
		(
			(
				all of ($a*) 
				and 
				(
					(3 of ($b*)) or (2 of ($b*) and 2 of ($c*)) or (2 of ($c*) and (2 of ($d*) or 1 of ($e*)))
				)
			) 
			or
			($a2 and 3 of ($b*) and 2 of ($c*) and (2 of ($d*) or ( 1 of ($d*) and 1 of ($e*))))
		)	
}
rule CCAvenueTracker_a
{
	meta:
		description = "All CCAvenue SDK Apps"
	condition:
		androguard.activity("com.ccavenue.indiasdk.PayOptionsActivity")		
}
rule koodous_jaaaaa: official
{
	condition:
		androguard.service("com.shunwang.service.CoreService")		
}
rule sdks_a
{
	condition:
		androguard.app_name(/bank/)
}
rule AadhaareKYCTracker_a
{
	meta:
		description = "This rule detects potential Aadhaar eKYC apps"
	strings:
		$a = "Aadhaar"
		$b = "eKYC"
		$c = "eSign"		
	condition:
		(($a) and ($b or $c)) and
		androguard.permission(/android.permission.INTERNET/)
}
rule DigitalLockerTracker_a
{
	meta:
		description = "This rule detects DigitalLocker SDK"
	strings:
		$a = "https://api.digitallocker.gov.in/"
		$b = "https://api.digitallocker.gov.in/public/oauth2/1/token"
		$c = "https://api.digitallocker.gov.in/public/oauth2/1/authorize"		
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)
}
rule could_be_packer_b: packer
{
    meta:
        description = "Generic Packer"
    strings:
        $a = /assets\/.{1,128}\.dex/
        $b = /assets\/[A-Za-z0-9.]{2,50}\.dex/
		$zip_head = "PK"
        $manifest = "AndroidManifest.xml"
    condition:
        ($a or $b) and
		($zip_head at 0 and $manifest and #manifest >= 2)
}
rule koodous_kaaaaa: official
{
	meta:
		description = "InMemoryDexClassLoader"
	strings:
		$a = "InMemoryDexClassLoader"
	condition:
		$a
}
rule bs_packer_a: packer
{
	meta:
		description = "CrackProof packer"
	strings:
		$j_do_asm_syscall = {
			00 48 2D E9 //   PUSH {R11,LR}
			04 B0 8D E2 //   ADD  R11, SP, #4
			28 D0 4D E2 //   SUB  SP, SP, #0x28
			10 00 0B E5 //   STR  R0, [R11,#var_10]
			14 10 0B E5 //   STR  R1, [R11,#a1]
			18 20 0B E5 //   STR  R2, [R11,#a2]
			1C 30 0B E5 //   STR  R3, [R11,#a3]
			00 30 A0 E3 //   MOV  R3, #0
			08 30 0B E5 //   STR  R3, [R11,#r]
			08 30 9B E5 //   LDR  R3, [R11,#a6]
			00 30 8D E5 //   STR  R3, [SP,#0x2C+var_2C] ; a5
			0C 30 9B E5 //   LDR  R3, [R11,#a7]
			04 30 8D E5 //   STR  R3, [SP,#0x2C+var_28] ; a6
			00 30 A0 E3 //   MOV  R3, #0
			08 30 8D E5 //   STR  R3, [SP,#0x2C+var_24] ; a7
			10 30 1B E5 //   LDR  R3, [R11,#var_10]
			0C 30 8D E5 //   STR  R3, [SP,#0x2C+svc_nr] ; svc_nr
			14 00 1B E5 //   LDR  R0, [R11,#a1] ; a1
			18 10 1B E5 //   LDR  R1, [R11,#a2] ; a2
			1C 20 1B E5 //   LDR  R2, [R11,#a3] ; a3
			04 30 9B E5 //   LDR  R3, [R11,#a5] ; a4
			?? ?? ?? EB //   BL   do_asm_syscall
			00 30 A0 E1 //   MOV  R3, R0
			08 30 0B E5 //   STR  R3, [R11,#r]
			08 30 1B E5 //   LDR  R3, [R11,#r]
			10 00 1B E5 //   LDR  R0, [R11,#var_10] ; svc_nr
			03 10 A0 E1 //   MOV  R1, R3  ; r
			?? ?? ?? EB //   BL   sub_4D78C
			00 30 A0 E1 //   MOV  R3, R0
			08 30 0B E5 //   STR  R3, [R11,#r]
			08 30 1B E5 //   LDR  R3, [R11,#r]
			03 00 A0 E1 //   MOV  R0, R3
			04 D0 4B E2 //   SUB  SP, R11, #4
			00 88 BD E8 //   POP  {R11,PC}
		}
		$do_asm_syscall = {
			FE 4F 2D E9  //  PUSH  {R1-R11,LR}
			2C B0 8D E2  //  ADD   R11, SP, #0x2C
			04 40 9B E5  //  LDR   R4, [R11,#a5]
			08 50 9B E5  //  LDR   R5, [R11,#a6]
			0C 60 9B E5  //  LDR   R6, [R11,#a7]
			10 70 9B E5  //  LDR   R7, [R11,#svc_nr]
			00 00 00 EF  //  SVC   0
			FE 8F BD E8  //  POP   {R1-R11,PC}
		}
	condition:
		all of them
}
rule sec_a: v1
{
	condition:
		androguard.package_name(/seC./) 
}
rule DigioESignSDKTrackerActivity_a
{
	meta:
		description = "All Digio eSign SDK Apps"
	strings:
		$a = "https://ext.digio.in"
	condition:
		($a or
		androguard.activity("com.digio.in.esign2sdk.DigioEsignActivity"))
}
rule eicar_substring_test_a {
    meta:
        description = "Standard AV test, checking for an EICAR substring"
        author = "Austin Byers | Airbnb CSIRT"
    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        all of them
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
rule icici_a
{
	meta:
		description = "Rule to find fakebank"
	condition:
		not androguard.package_name(/com.csam.icici.bank.imobile/) and
		androguard.app_name("icici") and not androguard.certificate.issuer(/O=ICICI BANK/)		
}
rule hdfc_a
{
	meta:
		description = "Rule to find fakebank"
	condition:
		not androguard.package_name(/com.snapwork.hdfcbank/) and
		androguard.app_name("hdfc") and not androguard.certificate.issuer(/O=Snapwork/)			
}
rule axis_a
{
	meta:
		description = "Rule to find fakebank"
	condition:
		not androguard.package_name(/com.axis.mobile/) and
		androguard.app_name("axis") and not androguard.certificate.issuer(/O=AXIS BANK/)			
}
rule skype_a: notofficial
{
	meta:
		description = "Skype not valit key"
	condition:
		androguard.package_name("com.skype.raider") and
		not androguard.certificate.sha1("385567F1AEFB2647E8B42430C9AAF6259619C99C") and
		not androguard.certificate.sha1("93D59489E99C8FBE54F75C90EA87A76E86937C9C") 
}
rule CreditVidyaTracker_a
{
	meta:
		description = "This rule detects CreditVidya SDK"
	strings:
		$a = "https://api.creditvidya.com"
		$b = "https://api.creditvidya.com/sdk/api/"
		$c = "https://api.creditvidya.com/sdk/api/token/v3"		
	condition:
		($a or $b or $c) and
		androguard.permission(/android.permission.INTERNET/)
}
rule secenh_a: packer
{
  meta:
	description = "Secenh"
	sample = "0709d38575e15643f03793445479d869116dca319bce2296cb8af798453a8752"
	author = "Nacho Sanmillan"
  strings:
	$a1 = "assets/libseceh.so"
	$a2 = "assets/libseceh_x86.so"
	$b1 = "assets/respatcher.jar"
	$b2 = "assets/res.zip"
  condition:
	1 of ($a*) 
	and 1 of ($b*)
}
rule koodous_laaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "ativar o servi"
		$b = "acessiblidade"
	condition:
		$a and $b
}
rule koodous_maaaaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "Falha na comunica"
		$b = "Carregando..."
		$c = "com servidor."
		$d = "aplicada com sucesso"
	condition:
		$a and $b and $c and $d
}
rule marcher_v2_b
{
	meta:
		description = "Detect marcher based on activity, service, receiver names."
		sample = "d7ff6de3f8af4af7c740943af3aaaf631a8baec42090f902bd7517e0190a1a21"
	condition:
		androguard.activity(/\.p0[0-9]{2}[a-z]\b/) and
		androguard.service(/\.p0[0-9]{2}[a-z]\b/) and
		androguard.receiver(/\.p0[0-9]{2}[a-z]\b/)
}
rule koodous_naaaaa: official
{
	meta:
		description = "This rule detects apps with bluetooth permissions"
	condition:
		androguard.permission(/android.permission.BLUETOOTH/) or
		androguard.permission(/android.permission.BLUETOOTH_ADMIN/)
}
rule storage_a
{
	meta:
		description = "This rule detects READ_SOCIAL_STREAM"
	condition:
		androguard.permission(/android.permission.READ_SOCIAL_STREAM/)
}
rule koodous_oaaaaa: official
{
	meta:
		description = "GitHub"
	strings:
		$a = "github.com"
	condition:
		$a or
		androguard.url(/github\.com/) or 
		cuckoo.network.dns_lookup(/github\.com/)
}
rule koodous_paaaaa: official
{
	meta:
		description = "https://blog.zimperium.com/fake-whatsapp-real-malware-zlabs-discovered/"
		sample = "1daa6ff47d451107b843be4b31da6e5546c00a164dc5cfbf995bac24fef3bc6d "
	condition:
		androguard.url(/systemofram\.com/) or 
		cuckoo.network.dns_lookup(/systemofram\.com/)
}
rule smstrojan_a: smstrojan
{
	meta:
		description = "Android album-like malware, contains malicious apk."
		sample = "8d67c9640b831912a124f3506dc5fba77f18c4e58c8b0dad972706864f6de09c"
	strings:
		$a = "send Message to"
		$b = "Tro instanll Ok"
		$c = "ois.Android.xinxi.apk"
	condition:
		all of them
}

rule findbutton_a
{
	condition:
		cuckoo.network.dns_lookup(/www.ub7o.com/) or
		cuckoo.network.dns_lookup(/www.lemonmobi.com/) or
		cuckoo.network.dns_lookup(/www.woomobi.com/)	or
		cuckoo.network.dns_lookup(/new.havefunonyourphone.com/) or 
		cuckoo.network.dns_lookup(/api.jsian.com/) or
		cuckoo.network.dns_lookup(/igbli.com/) or
		cuckoo.network.dns_lookup(/api.jesgoo.com/) or
		cuckoo.network.dns_lookup(/api.moogos.com/) or
		cuckoo.network.dns_lookup(/api.smallkoo.com/) or
		cuckoo.network.dns_lookup(/cdn.jesgoo.com/)
}
rule koodous_qaaaaa: official
{
	meta:
		description = "This rule detects the overdraw applications"
	condition:
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/)
}
rule koodous_raaaaa: official
{
	meta:
		description = "Looks up Toast Overlayer Attacking Apps"
	strings:
		$a = "device_policy"
		$b = "clipboard"
		$c = "power"
		$d = "com.android.packageinstaller"
		$e = "bgAutoInstall"
	condition:
		$a and
		$b and
		$c and 
		$d and 
		$e and
		androguard.activity(/MyAccessibilityServiceTmp/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/)
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
rule ElGato_a: Ransom
{
	meta:
		description = "https://blogs.mcafee.com/mcafee-labs/cat-loving-mobile-ransomware-operates-control-panel/"
  strings:
        $text_string = "MyDifficultPassw"
		$text_2 = "EncExc"
    condition:
       $text_string or $text_2
 }
rule SeSeAOV_a: SexApp
{
	meta:
		sample = "f93222a685f45487732e1692d6c1cbeb3748997c28ca5d61c587b21259791599"
	condition:
		cuckoo.network.dns_lookup(/h.\.tt-hongkong.com/)
}
rule koodous_saaaaa: official
{
	meta:
		description = "http://seclab.safe.baidu.com/2017-11/sysghost.html"
	condition:
		androguard.url(/iappease\.com\.cn/) or
		androguard.url(/ixintui\.com/) or
		androguard.url(/wit-wifi\.com/) or
		cuckoo.network.dns_lookup(/iappease\.com\.cn/) or
		cuckoo.network.dns_lookup(/ixintui\.com/) or
		cuckoo.network.dns_lookup(/wit-wifi\.com/)
}
rule ezeeworld_a
{
	meta:
		description = "This rule detects application including Ezeeworld SDK"
	condition:
		androguard.receiver("com.ezeeworld.b4s.android.sdk.monitor.SystemEventReceiver")
}
rule MalignantFeatures_b: jcarneiro
{
	meta:
		description = "This rule detects the presence of Malignant Features"
	condition:
		androguard.service(/com.app.BestService/)	or
		androguard.activity(/com.app.MainBaseActivity/)	or
		androguard.activity(/com.cie.one.reward.popup.OneRewardPopup/)	or
		androguard.activity(/ContentProviderList_com.adobe.air.CameraUIProvider/)	or
		androguard.activity(/ServiceList_com.sgn.dlc.service.DownloaderService/)	or
		androguard.activity(/UsedPermissionsList_android.permission.DISABLE_KEYGUARD/)	or
		androguard.activity(/ActivityList_com.chartboost.sdk.CBDialogActivity/)	or
		androguard.activity(/ServiceList_com.flymob.sdk.common.server.FlyMobService/)	or
		androguard.activity(/ServiceList_io.mobby.sdk.SyncService/)	or
		androguard.activity(/ServiceList_io.mobby.loader.android.SyncService/)	or
		androguard.activity(/BroadcastReceiverList_io.mobby.loader.android.receiver.SDCardMountedReceiver/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
		/)	or
		androguard.activity(/
}
rule AndroidAdServer_a
{
	meta:
		description = "Rule to catch APKs speaking to a noisy ad server"
	condition:
		androguard.url(/123\.56\.205\.151/) or
		androguard.url("123.56.205.151") or
		cuckoo.network.dns_lookup(/123\.56\.205\.151/)
}
rule testRule_a
{
	condition:
		androguard.permission(/com.massage.aptoide.permission.C2D_MESSAGE/) or
		androguard.permission(/android.permission.SET_ANIMATION_SCALE/) or
		androguard.permission(/org.catrobat.catroid.generated27539.permission.C2D_MESSAGE/) or
		androguard.permission(/com.massage.aptoide.permission.C2D_MESSAGE/) or
		androguard.permission(/android.permission.READ_APP_BADGE/) or
		androguard.permission(/me.everything.badger.permission.BADGE_COUNT_READ/) or
		androguard.permission(/me.everything.badger.permission.BADGE_COUNT_WRITE/) or
		androguard.permission(/com.mytriber.me.Tb565fa76620d4290a8d317d3f38e82da.permission.C2D_MESSAGE/) or
		androguard.permission(/com.gamedevltd.modernstrike.bgtdfg.permission.C2D_MESSAGE/) or
		androguard.permission(/com.jumpgames.pacificrim.permission.C2D_MESSAGE/) or
		androguard.permission(/io.wifimap.wifimap.gcm.permission.C2D_MESSAGE/) or
		androguard.permission(/nullsclash.night.rel.permission.C2D_MESSAGE/) or
		androguard.permission(/com.yd.android.mtstrikeru.permission.JPUSH_MESSAGE/) or
		androguard.permission(/com.yd.android.mtstrikeru.permission.C2D_MESSAGE/) or
		androguard.permission(/com.hecorat.screenrecorder.free.permission.C2D_MESSAGEdf/) or
		androguard.permission(/com.sec.enterprise.permission.MDM_PROXY_ADMIN_INTERNAL/) or
		androguard.permission(/android.permission.BIND_DEVICE_ADMIN/) or
		androguard.permission(/android.permission.sec.ENTERPRISE_DEVICE_ADMIN/) or
		androguard.permission(/com.sec.enterprise.knox.permission.KNOX_ATTESTATION/) or
		androguard.permission(/android.permission.sec.MDM_APP_BACKUP/) or
		androguard.permission(/com.sec.enterprise.mdm.permission.BROWSER_PROXY/) or
		androguard.permission(/android.permission.ACCESS_MOCK_LOCATION/) or
		androguard.permission(/android.permission.SET_PROCESS_LIMIT/) or
		androguard.permission(/com.sec.enterprise.knox.cloudmdm.smdms.permission.SAMSUNG_MDM_SERVICE/) or
		androguard.permission(/android.permission.sec.MDM_APP_MGMT/) or
		androguard.permission(/android.permission.sec.MDM_APP_PERMISSION_MGMT/) or
		androguard.permission(/android.permission.sec.MDM_BLUETOOTH/) or
		androguard.permission(/android.permission.sec.MDM_INVENTORY/) or
		androguard.permission(/android.permission.sec.MDM_EXCHANGE/) or
		androguard.permission(/android.permission.sec.MDM_ROAMING/) or
		androguard.permission(/android.permission.sec.MDM_WIFI/) or
		androguard.permission(/android.permission.sec.MDM_SECURITY/) or
		androguard.permission(/android.permission.sec.MDM_HW_CONTROL/) or
		androguard.permission(/android.permission.sec.MDM_RESTRICTION/) or
		androguard.permission(/android.permission.sec.MDM_LOCATION/) or
		androguard.permission(/android.permission.sec.MDM_CALLING/) or
		androguard.permission(/android.permission.sec.MDM_EMAIL/) or
		androguard.permission(/android.permission.sec.MDM_VPN/) or
		androguard.permission(/android.permission.sec.MDM_APN/) or
		androguard.permission(/android.permission.sec.MDM_PHONE_RESTRICTION/) or
		androguard.permission(/android.permission.sec.MDM_BROWSER_SETTINGS/) or
		androguard.permission(/android.permission.sec.MDM_DATE_TIME/) or
		androguard.permission(/android.permission.sec.MDM_ENTERPRISE_VPN/) or
		androguard.permission(/android.permission.sec.MDM_FIREWALL/) or
		androguard.permission(/android.permission.sec.MDM_REMOTE_CONTROL/) or
		androguard.permission(/android.permission.sec.MDM_KIOSK_MODE/) or
		androguard.permission(/android.permission.sec.MDM_AUDIT_LOG/) or
		androguard.permission(/android.permission.sec.MDM_CERTIFICATE/) or
		androguard.permission(/android.permission.sec.MDM_SMARTCARD/) or
		androguard.permission(/android.permission.sec.MDM_SEANDROID/) or
		androguard.permission(/android.permission.sec.MDM_LDAP/) or
		androguard.permission(/android.permission.sec.MDM_LOCKSCREEN/) or
		androguard.permission(/android.permission.sec.MDM_GEOFENCING/) or
		androguard.permission(/android.permission.sec.MDM_BLUETOOTH_SECUREMODE/) or
		androguard.permission(/android.permission.sec.MDM_MULTI_USER_MGMT/) or
		androguard.permission(/android.permission.sec.MDM_LICENSE_LOG/) or
		androguard.permission(/android.permission.sec.MDM_DUAL_SIM/) or
		androguard.permission(/android.permission.sec.MDM_ENTERPRISE_SSO/) or
		androguard.permission(/android.permission.sec.MDM_ENTERPRISE_ISL/) or
		androguard.permission(/android.permission.sec.MDM_ENTERPRISE_CONTAINER/) or
		androguard.permission(/android.permission.sec.ENTERPRISE_MOUNT_UNMOUNT_ENCRYPT/) or
		androguard.permission(/android.permission.sec.ENTERPRISE_CONTAINER/) or
		androguard.permission(/com.sec.enterprise.knox.KNOX_GENERIC_VPN/) or
		androguard.permission(/com.sec.enterprise.knox.permission.KNOX_DEACTIVATE_LICENSE/) or
		androguard.permission(/com.sec.enterprise.knox.permission.KNOX_CCM/) or
		androguard.permission(/android.permission.sec.MDM_UMC_INTERNAL/) or
		androguard.permission(/com.sec.enterprise.knox.permission.KNOX_CERTENROLL/) or
		androguard.permission(/com.sec.enterprise.mdm.permission.MDM_SSO/) or
		androguard.permission(/com.sec.enterprise.knox.KNOX_CONTAINER_VPN/) or
		androguard.permission(/com.samsung.android.gencertservice.permission.SERVICE_BIND/) or
		androguard.permission(/com.sec.android.SAMSUNG_AASASERVICE/) or
		androguard.permission(/com.fde.avpevolution.bfgtwe.permission.C2D_MESSAGE/) or
		androguard.permission(/com.rsupport.mobizen.live.permission.C2D_MESSAGE/) or
		androguard.permission(/com.gameloft.android.ANMP.GloftLBCR.permission.C2D_MESSAGEzy/) or
		androguard.permission(/glshare.permission.ACCESS_SHARED_DATAzy/) or
		androguard.permission(/com.paradoxplaza.prisonarchitect.permission.C2D_MESSAGE/) or
		androguard.permission(/com.gameloft.android.ANMP.GloftG4HM.bddf.permission.C2D_MESSAGE/) or
		androguard.permission(/android.launcher.permission.INSTALL_SHORTCUT/) or
		androguard.permission(/com.kilooclash.clashofclans.permission.C2D_MESSAGE/) or
		androguard.permission(/com.rockstargames.bully.bfgtwe.permission.C2D_MESSAGE/) or
		androguard.permission(/com.giantssoftware.fs18.google.permission.C2D_MESSAGE/) or
		androguard.permission(/com.tct.launcher.permission.READ_SETTINGS/) or
		androguard.permission(/com.tct.launcher.permission.WRITE_SETTINGS/) or
		androguard.permission(/com.tct.launcher.permission.RECEIVE_LAUNCH_BROADCASTS/) or
		androguard.permission(/com.tct.launcher.permission.RECEIVE_FIRST_LOAD_BROADCAST/) or
		androguard.permission(/android.permission.ACCESS_OTA_DATA/) or
		androguard.permission(/com.tct.email.permission.ACCESS_PROVIDER/) or
		androguard.permission(/com.tct.launcher.permission.C2D_MESSAGE/) or
		androguard.permission(/com.supercell.clashofclans.permission.C2D_MESSAGEpgxu/)
}
rule mobby_a
{
	strings:
		$a = "io/mobby/sdk/receiver"
		$b = "io/mobby/sdk/activity"
		$c = "mobby"
	condition:
		any of them
}
rule koodous_taaaaa: official
{
	meta:
		author = "Sdesai"
		sample = "df8b64f1e3843b50735d5996bd980981"
	strings:
		$hash="SHA1:dda09d19354d25833153d64077cd396c970bb1d4"
		$url="AMStrings:https://www.Spy-datacenter.com/send_data.php"
		$per_1="Permission:android.permission.RECEIVE_SMS"
		$per_2="Permission:android.permission.RECORD_AUDIO"
		$str_2="AMStrings:recording_phone"
		$str_3="AMStrings:disable_call_recording"
		$str_4="AMStrings:#takepic"
		$str_5="AMStrings:#recordaudio"
		$str_6="AMStrings:#lockphone"
		$str_7="AMStrings:unlock_phone_pass"
		$str_8="AMStrings:take_pic_front"
		$str_9="android.intent.action.NEW_OUTGOING_CALL"
		$str_10="AMStrings:content://call_log/calls"
		$str_11="AMStrings:content://com.android.chrome.browser/history"
		$str_13="AMStrings:hide_icon"
	condition:
		($hash and $url and $per_1 and $per_2) or (all of ($str_*))
}
rule TikTok_1_a: Malware
{
	meta:
		description = "TikTok Malware"
		sample = "157a068dc647e50aa8b55efb2d7bfe9ddbffc06299108bf31add16056737829f"
	strings:
		$name_1 = { 62 96 97 F3 }
		$name_2 = { 70 6B 5C 71 }
		$name_3 = { 89 7F 74 DC 89 C6 98 91 }
		$name_4 = { 4E CA 65 E5 59 34 67 61 }
	condition:
		any of ($name_*) and
		not androguard.certificate.sha1("00a584e375b5573c89e1f06f5cf60d0d65ddb632")
}
rule TikTok_1_b: Malware
{
	meta:
		description = "TikTok Malware"
		sample = "157a068dc647e50aa8b55efb2d7bfe9ddbffc06299108bf31add16056737829f"
	strings:
		$name_1 = { 62 96 97 F3 }
		$name_2 = { 70 6B 5C 71 }
		$name_3 = { 89 7F 74 DC 89 C6 98 91 }
		$name_4 = { 4E CA 65 E5 59 34 67 61 }
	condition:
		any of ($name_*) and
		not androguard.certificate.sha1("00a584e375b5573c89e1f06f5cf60d0d65ddb632")
}
rule koodous_uaaaaa: official
{
	meta:
		description = "Android.Cerberus"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		  $a = "grabbing_google_authenticator2"
        $b = "run_app"
        $c = "change_url_connect"
        $d = "grabbing_pass_gmail"
        $d2 = "change_url_recover"
        $d3 = "send_mailing_sms"
        $d4 = "access_notifications"
        $d5 = "sms_mailing_phonebook"
	condition:
		all of them
}
rule Joker_a
{
	meta:
		author = "Tom_Sara"
		description = "This rule detects Joker Malware"
	strings:
	$required_1 = "getNetworkOperator"
	$required_2 = "getLine1Number"
	$required_3 = "getDeviceId"
condition:
	all of ($required_*) and 		
	androguard.activity("/com.google.android.gms.ads.AdActivity/")
}
rule android_joker_d {
meta:
	description = "To Detect Joker Trojans"
condition:
        androguard.activity("com.google.android.gms.ads.AdActivity")
}
rule koodous_vaaaaa: official
{
	meta:
		description = "Banker.Android.BlackRock"
		sample = "32d2071ea8b7d815ab3455da2770b01901cef3fc26b9912f725a0a7de2f7d150"
	strings:
		 $a = "26kozQaKwRuNJ24t"
        $a1 = "Send_SMS"
        $a2 = "Flood_SMS"
        $a3 = "Download_SMS"
        $a4 = "Spam_on_contacts"
        $a5 = "Change_SMS_Manager"
        $a6 = "Run_App"
        $a7 = "StartKeyLogs"
        $a8 = "StopKeyLogs"
        $a9 = "StartPush"
        $a0 = "StopPush"
        $a10 = "Hide_Screen_Lock"
        $a11 = "Unlock_Hide_Screen"
        $a12 = "Admin"
        $a13 = "Profile"
        $a14 = "Start_clean_Push"
        $a15 = "Stop_clean_Push"
	condition:
		 all of them
}
rule koodous_aa: BTC_ETH
{
	meta:
		description = "This rule detects bitcoin and ethereum"
	strings:
		$a = "/^(0x)?[0-9a-fA-F]{40}$/"
		$b = "/^(1|3)[a-zA-Z0-9]{24,33}$/"
		$c = "/^[^0OlI]{25,34}$/"
	condition:
		$a or ($b and $c)		
}
rule UntrustedDevelopers_a
{
	meta:
		description = "This rule detects applications by untrusted developers."
	condition:
		androguard.certificate.sha1("A623DE0D0517731162C0D50CE439AFFCAA4B3A8B") and
		androguard.certificate.sha1("166073937926629F3FFE054BE80850B7F4CEFFEB")
}
rule Minergate_a
{
	meta:
		description = "This rule detects the Minergate string"
	strings:
		$a = "minergate.com"
	condition:
		$a 
}
rule Banker_d: BlackRock
{
	meta:
        description = "Trojan targeting Banks - BlackRock"
	strings:
		$c2_1 = "gate.php" nocase
		$c2_2 = "inj" nocase
		$string_1 = "imei" nocase
		$string_2 = "banks" nocase
		$string_3 = "AES" nocase
		$cmd_1 = "injActive" nocase
		$cmd_2 = "android_id" nocase
		$cmd_3 = "cardNumber" nocase
	condition:
		1 of ($c2_*)
		and 2 of ($string_*)
		and 2 of ($cmd_*)
		and (
			androguard.permission(/android.permission.BIND_ACCESSIBILITY_SERVICE/)
		)
}
rule ransomware_generic_a
{
	strings:
		$notice_1 = "All your files are encrypted" nocase
		$notice_2 = "Your phone is locked until paymenti" nocase
		$notice_3 = "your files have been encrypted!" nocase
		$notice_4 = "your Device has been locked" nocase
		$notice_5 = "All information listed below successfully uploaded on the FBI Cyber Crime Depar" nocase
		$notice_6 = "Your phone is locked , and all your personal data" nocase
	condition:
		1 of them	
}
rule BlackRock_a
{
	meta:
		description = "This rule detects the BlackRock malware"
		sample = "81fda9ff99aec1b6f7b328652e330d304fb18ee74e0dbd0b759acb24e7523d8c"
		src = "https://www.threatfabric.com/blogs/blackrock_the_trojan_that_wanted_to_get_them_all.html"
	condition:
		androguard.app_name("Google Update") and 
		androguard.receiver(/Smsmnd.MmsReceiver/i) and
		androguard.receiver(/Admins/i) and
		androguard.receiver(/AlarmBroadcastReceiver/i)
}
rule videogames_c
{
    meta:
        description = "Rule to catch APKs with package name match with videogame"
    condition:
        androguard.package_name(/videogame/)
}
rule PornSlocker_b
{
	meta:
		description = "This rule detects some common used pictures or other files in SLocker / PornLocker variants"
strings:
	  $ = "+peNAqsEDqAiIB5C1bI1ABJUQhw"
      $ = "20j5H7HXFJMGsBIGYI426RQpQnQ"
      $ = "4Sx38f55G9Jr+XOyr3jbjky7fD4"
      $ = "5zokrOTkM2EsbSZIeCjbKBc4ci4"
      $ = "OxFElpi2+oBqlQHh3jk+3fMD9Y8"
      $ = "Wc1rLTQNhJtMbIiyNxmyw1jcNS8"
      $ = "YPcRkdktCfVzEA4Fd83WkmXnO3w"
      $ = "ZqjexisfZj0WmcuFhrJhh6jB2Gk"
      $ = "pH7PIBTiJ94EaJWpZa1ITsUP1FI"	 
	condition:
		1 of them
}
rule Trojan_g: trojans_ttp
{
	meta:
        description = "trojans bankers com overlay e/ou acessibilidade"
		author = "Ialle Teixeira"
	strings:
		$c2_1 = "canairizinha" nocase
		$c2_2 = "conexao_BR" nocase
		$c2_3 = "progertormidia" nocase
		$c2_4 = "$controladores_BR" nocase
		$c2_5 = "Anywhere Software" nocase
		$c2_6 = "starter_BR" nocase
		$c2_7 = "b0z" nocase
		$c2_8 = "bolsonaro" nocase
	condition:
      androguard.package_name("com.itau") or any of them
}
rule android_bankbot_a
{
	meta:
		description = "This rule detects possible android bankbot like Cerberus or Anubis"
	strings:
		$a = "accessibilityservice"
	condition:
		$a and 
        androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
        androguard.permission(/android.permission.SEND_SMS/) and
        androguard.permission(/android.permission.WAKE_LOCK/) and
        androguard.permission(/android.permission.RECEIVE_SMS/) and
        androguard.permission(/android.permission.READ_SMS/) and
        androguard.permission(/android.permission.RECORD_AUDIO/) and
        androguard.permission(/android.permission.READ_PHONE_STATE/) and
        androguard.permission(/android.permission.FOREGROUND_SERVICE/) and
        androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
        androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
        androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
        androguard.permission(/android.permission.CALL_PHONE/) and
        androguard.permission(/android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/) and
        androguard.permission(/android.permission.READ_CONTACTS/)
}
rule xmrigStrings_a
{
    strings:
        $fee = "fee.xmrig.com" wide ascii
        $nicehash = "nicehash.com" wide ascii
        $minergate = "minergate.com" wide ascii
        $stratum = "stratum+tcp://" wide ascii
    condition:
       $fee and
       $nicehash and
       $minergate and
       $stratum 
}
rule test_c: official
{
	condition:
		androguard.filter("android.intent.action.PHONE_STATE")
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
rule dexprotector_old_a: packer
{
  meta:
    description = "DexProtector"
  strings:
    $encrptlib_1 = "assets/dp.arm-v7.art.kk.so"
    $encrptlib_2 = "assets/dp.arm-v7.art.l.so"
    $encrptlib_3 = "assets/dp.arm-v7.dvm.so"
    $encrptlib_4 = "assets/dp.arm.art.kk.so"
    $encrptlib_5 = "assets/dp.arm.art.l.so"
    $encrptlib_6 = "assets/dp.arm.dvm.so"
    $encrptlib_7 = "assets/dp.x86.art.kk.so"
    $encrptlib_8 = "assets/dp.x86.art.l.so"
    $encrptlib_9 = "assets/dp.x86.dvm.so"
    $encrptcustom = "assets/dp.mp3"
  condition:
    2 of ($encrptlib_*) and $encrptcustom
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
rule koodous_ba: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$service1="TTT.Sberbank"
		$service2="TTT.CardService"
		$service3="MainService"
		$service4="TTT.Avito"
		$service5="TTT.Alpha"
		$service6="TTT.Ali"
		$service7="TTT.vtb24"
		$service8="TTT.ural"
	condition:
	any	of them and  androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED") and androguard.filter(/ACTION_DEVICE_ADMIN_DISABLED/)
	}
rule SmsFraudUsingUrls_a: smsfraud
{
	meta:
		cluster_url = "https://koodous.com/apks?search=57392579046725034bb95dd1f60dc6de61b4ea8dc8a74c6567f389874248dd85%20OR%20365264012541ee0991afc7344e0f8c34e6a0166b76b7b3e82f2a2458262aca79%20OR%20c3d41e5b91c1c436fcaf3f3ccf053b17a6c9ff609d5b75dbbf162a3aaf211992%20OR%2087aa082a58590a3ed721c43ada4974d2257012748b25377815a8c57be5212be6%20OR%208fa10258025b49963793d9864ba344d426f2f952a7b082a9a0e6a4888ce55ba7%20OR%2034c4d8a7947c83c773af1bc682d1a389ef8dc25e3d8ac02b2ecb469949be3a74%20OR%2013eebcb6b37d40267fdcfc1b778c3cd57a663ccea736fd6256aaa69666b6819f%20OR%20db96bf5052a29fb6b44c270bfb94294ce90f05dbc5aba7fcab3729a0ca89245c%20OR%20396ec6d18430abe8949ddc39cf10d008e189be9b41fff598cfde73a67987da5e%20OR%209a69a20ae5128e5646ac84334a1a86cdb6cba95d93c6bba5e6e143fa5f6ad226%20OR%200b14afb604707f1348d3e6a3d949255033e233f1300a4346b37dda69edbddc3c%20OR%209f8a76bf08c49d2ea9984303210ad65e57d39504a3f6a032e6126039039d4689%20OR%203c9d52e75a37645a726bd5373f176767eab3c67a6e97f12650f81a6faa7d7598%20OR%20a7fb9d9317d2593da7b45af032e16729612378d9bdc124812348bc3fb720fd9a%20OR%203d314d5ba462fa1bfb1f940c9760fe925318e1ec3990190f238be44cf1bded8a%20OR%20f64609a98cc6e3f23b210bc1d87a2d1cd969b4a7561f2d18073c7804ca8e4b93%20OR%203a9e7545301c7dee2d3e90ab350710b30acf4aea30e221b88829761c91f24ca1%20OR%20cb7a6e6c60ae51e3eb38e3956b46de607769aa37e172a62c40579487cb36ebd2%20OR%20aa72e50e45767bf57f0edd6874fc79430dec6bd9314b50c3ba020748ed5c17c2%20OR%203eabcb500ca484091897365263e48add7904ad1e67956a09cffb94f60ba0389d"
		description = "This rule should match applications that send SMS"
	condition:
		androguard.url(/tools\.zhxapp\.com/)
		or androguard.url(/app\.tbjyz\.com\/tools\/zhxapp_hdus(\w+)?/)
}
rule Test7_a
{
	condition:
		androguard.package_name("com.estrongs.android.pop")
}
rule kevdroid_a
{
	meta:
		description = "This rule detects suspicious KevDroid certificate"
		sample1 = "f33aedfe5ebc918f5489e1f8a9fe19b160f112726e7ac2687e429695723bca6a"
		sample2 = "c015292aab1d41acd0674c98cd8e91379c1a645c31da24f8d017722d9b942235"
		author = "DMA"
	condition:
		androguard.certificate.sha1("A638D0C9CC18AC0E5D2EC83144EA237DFFA1FA2A")
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
rule koodous_ca: official
{
	meta:
		description = "Fake korea Banker"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "kkk.kakatt.net:3369/send_pro"
	condition:
		$a
}
rule Xafecopy_a
{
	meta:
		author = "Ransombleed"
		description = "Xafecopy detection rule"
	strings:
        $a =  "assets/chazhaoanniu.js"
		$a2 = "assets/chuliurl.js"
		$a3 = "assets/monidianji.js"
		$a4 = "assets/shuruyzm.js"
        $b =  "//Your system is optimizing"
        $b2 = "Congratulations, you have a chance to use the world's popular battery tool."
        $b3 = "Clean Up Assistant is a small, stylish, elegant application that can help you focus on the current battery charge percentage of your circumstances Android device, and even can be used as energy saving device."
	condition:
		1 of ($a*) or 2 of ($b*)
}
rule android_tempting_cedar_spyware_a
{
	meta:
    	Author = "@X0RC1SM"
        Date = "2018-03-06"
        Reference = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"
	strings:
		$PK_HEADER = {50 4B 03 04}
		$MANIFEST = "META-INF/MANIFEST.MF"
		$DEX_FILE = "classes.dex"
		$string = "rsdroid.crt"
	condition:
    	$PK_HEADER in (0..4) and $MANIFEST and $DEX_FILE and any of ($string*)
}

rule Banker_Acecard_b
{
meta:
author = "https://twitter.com/SadFud75"
more_information = "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"
samples_sha1 = "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 53cca0a642d2f120dea289d4c7bd0d644a121252"
strings:
$str_1 = "Cardholder name"
$str_2 = "instagram.php"
condition:
((androguard.package_name("starter.fl") and androguard.service("starter.CosmetiqFlServicesCallHeadlessSmsSendService")) or androguard.package_name("cosmetiq.fl") or all of ($str_*)) and androguard.permissions_number > 19
}
rule Fake_Flash_Player_b
{
  meta:
       description = "Detects fake flashplayer apps"
	strings:
		$string_1 = "pay"
   condition:
	 $string_1 and
       (androguard.package_name(/com\.adobe\.flash/i) or androguard.app_name(/Adobe Flash/i)) 
}
rule QR_drop_a
{
	meta:
		description = "This rule detects malicious samples hiding behind QR apps"
		blog = "https://nakedsecurity.sophos.com/2018/03/23/crooks-infiltrate-google-play-with-malware-lurking-in-qr-reading-utilities/"
		sample = "66c770c15c9a3c380a7fdd51950a3797"
	condition:
		androguard.service(/android.support.graphics.base.BaseService/) and
		androguard.receiver(/android.support.graphics.broadcast.RestartServiceBroadCast/)
}
rule reddrop2_a
{
	meta:
		description = "This rule detects malicious samples belonging to Reddrop campaign"
		sample = "76b2188cbee80fffcc4e3c875e3c9d25"
	strings:
		$a_1 = "pay"
		$a_2 = "F88YUJ4"
	condition:
		all of ($a_*)
}
rule ChinesePorn_2_b
{
	meta:
		description = "This rule detects dirtygirl samples"
		sample = "aeed925b03d24b85700336d4882aeacc"
	condition:
		androguard.receiver(/com.sdky.lyr.zniu.HuntReceive/) and
		androguard.service(/com.sdky.jzp.srvi.DrdSrvi/)
}
rule HummingWhale_b
{
	meta:
		description = "A Whale of a Tale: HummingBad Returns, http://blog.checkpoint.com/2017/01/23/hummingbad-returns/"
		sample = "0aabea98f675b5c3bb0889602501c18f79374a5bea9c8a5f8fc3d3e5414d70a6"
	strings:
		$ = "apis.groupteamapi.com"
		$ = "app.blinkingcamera.com"
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

rule weixin_a: fakeapp
{
	strings:
		$decode_0 = "subindex"
		$decode_1 = "domain"
		$decode_2 = "system_jjss_limitCount"
		$start_0 = "startUpDebugTimer"
		$start_1 = "controlBizStart"
		$url_0 = "/cbase/client/record1"
		$log_0 = "DefaultUrlStart"
		$log_1 = "DeviceBasicInfoStart"
		$advert_0 = "advertlist"
		$advert_1 = "AdvertBrowser"
	condition:
		all of ($decode_*) or
		all of ($start_*) or
		all of ($url_*) or
		all of ($log_*) or
		all of ($advert_*) or
		cuckoo.network.dns_lookup(/www\.d3k9\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.144/) or
		cuckoo.network.dns_lookup(/www\.d7l9\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.142/) or
		cuckoo.network.dns_lookup(/www\.g5h9\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.149/) or
		cuckoo.network.dns_lookup(/www\.g7h9\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.225/) or
		cuckoo.network.dns_lookup(/www\.m4n6\.com/) or
		cuckoo.network.dns_lookup(/112\.213\.127\.191/)
}

rule yundong_24xia_a: fakeapp
{
	strings:
		$domain_0 = "yirenna.com"
		$domain_1 = "24xia.com"
		$domain_2 = "wapfit.com"
		$pkgname_0 = "com.yundong.dex"
		$pkgname_1 = "com.abc.demo"
		$pkgname_2 = "com.yundong.plugin"
		$pkgname_3 = "com.uc.addon."
		$pkgname_4 = "com.jiahe.school"
		$s1_0 = "UpdateDexService"
		$s1_1 = "AliveService"
		$s2_0 = "UpdatePluginService"
		$s2_1 = "getUpdateUrl"
		$s2_2 = "DEX_UPDATE_CHECK_FINISH"
		$s3_0 = "updateAppBean"
		$s3_1 = "DEX_DOWNLOAD_FINISHED"
		$s3_2 = "dexVersion"
		$s4_0 = "startUploadWifi"
		$s4_1 = "uploadWifiBeanList"
		$s5_0 = ".taskservice.UpdateDexService"
		$s6_0 = "requestWifiTask"
		$s6_1 = "getWifiKeyPassword"
		$s7_0 = "task/taskList.do?"
		$s7_1 = "TASK_URL"
	condition:
		any of ($domain_*) or
		any of ($pkgname_*) or
		all of ($s1_*) or
		all of ($s2_*) or
		all of ($s3_*) or
		all of ($s4_*) or
		all of ($s5_*) or
		all of ($s6_*) or
		all of ($s7_*) or
		androguard.package_name("com.abc.demo") or
		androguard.package_name("com.yundong.plugin") or
		androguard.package_name(/com.uc.addon./) or
		androguard.package_name("com.jiahe.school")
}
rule koodous_da: skymobi
{
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$a = "Java_com_skymobi_pay_common_util_LocalDataDecrpty_Decrypt"
		$b = "Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt"
	condition:
		all of them
}
rule WireX_b
{
	meta:
        description = "Evidences of WireX."
		sample = "168624d9d9368155b7601e7e488e23ddf1cd0c8ed91a50406484d57d15ac7cc3"
	strings:
		$1 = "axclick.store"
		$2 = "snewxwri"
   	condition:
    	1 of them
}
rule MMVideo_Camera_a: MMVideo
{
	meta:
		description = "This rule used to sort samples about 3457571382@qq.com"
	condition:
		cuckoo.network.dns_lookup(/35430\.com\.cn/) or
		cuckoo.network.dns_lookup(/338897\.com\.cn/) or
		cuckoo.network.dns_lookup(/33649\.com\.cn/)
}
rule koler_c: ransomware
{
	meta:
		description = "Koler Ransomware"
		sample = "b79916cb44be7e1312d84126cb4f03781b038d10"
		source = "https://www.bleepingcomputer.com/news/security/koler-android-ransomware-targets-the-us-with-fake-pornhub-apps/"
	strings:
		$fbi_1 = "FEDERAL BUREAU OF INVESTIGATION" nocase
		$fbi_2 = "FBI HEADQUARTER" nocase
		$porn = "child pornography" nocase
	condition:
		all of ($fbi_*)
		and $porn
		and androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/)
}
rule MUK_Banks_Trojan_a
{
	meta:
		description = "This rule detects Mazain banker"
		sample = "579b632213220f9fd2007ff6054775b7c01433f4d7c43551db21301b2800cd8c"
	strings:
		$ = "5.45.87.115"
		$ = "twitter.com"
	condition:
		1 of them
		and androguard.package_name("com.acronic")	
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
rule BOI_a
{
	meta:
		description = "This rule detects the BOI applications, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "com.bankofireland.mobilebanking"
		$m = "com.boi.tablet365"
	condition:
		any of them
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
rule MMVideo_Cfg_a: MMVideo
{
	meta:
		description = "This rule detects mmvideo by its online config info"
		sample = ""
		info = "http://xh0937.com/qchannel/url/getallurlbyname?name=wjurl"
	strings:
		$url_0 = "url1"
		$url_1 = "url2"
		$url_2 = "url3"
		$url_3 = "url4"
		$url_4 = "url5"
		$url_5 = "url6"
		$price_0 = "price2"
		$price_1 = "price3"
		$price_2 = "price4"
		$price_3 = "price5"
		$price_4 = "price6"
		$pic_0 = "picUrl"
		$pic_1 = "playUrl"
		$pic_2 = "tryNum"
		$pic_3 = "wxScanToggle"
		$pic_4 = "aliToggle"
		$pic_5 = "service"
		$channel = "/url/getallurlbyname"
	condition:
		all of ($url_*) or
		all of ($price_*) or
		all of ($pic_*) or 
		$channel
}

rule VT_Sonicspy_a: Spy
{
	meta:
		detail = "https://blog.lookout.com/sonicspy-spyware-threat-technical-research"
	strings:
		$ = "dt7C1uP3c2al6l0ib"
		$ = "not concteed"
	condition:
		all of them
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
rule PornSlocker_c
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
rule koodous_ea: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "service.adb.tcp.port"
	condition:
		$a	
}
rule dxshield_c: packer
{
  meta:
    description = "DxShield"
    url = "http://www.nshc.net/wp/portfolio-item/dxshield_eng/"
  strings:
    $decryptlib = "libdxbase.so"
    $res = "assets/DXINFO.XML"
  condition:
    ($decryptlib and $res)
}
rule appguard_c: packer
{
  meta:
    description = "AppGuard"
    url = "http://appguard.nprotect.com/en/index.html"
  strings:
    $stub = "assets/appguard/"
    $encrypted_dex = "assets/classes.sox"
  condition:
    ($stub and $encrypted_dex)
}
rule secneo_c: packer
{
  meta:
    description = "SecNeo"
    url = "http://www.secneo.com"
  strings:
    $encryptlib1 = "libDexHelper.so"
    $encryptlib2 = "libDexHelper-x86.so"
    $encrypted_dex = "assets/classes0.jar"
  condition:
    any of ($encrypted_dex, $encryptlib2, $encryptlib1)
}
rule dexprotector_d: packer
{
  meta:
    author = "Jasi2169"
    description = "DexProtector"
  strings:
    $encrptlib = "assets/dp.arm.so.dat"
    $encrptlib1 = "assets/dp.arm-v7.so.dat"
    $encrptlib2 = "assets/dp.arm-v8.so.dat"
    $encrptlib3 = "assets/dp.x86.so.dat"
    $encrptcustom = "assets/dp.mp3"
  condition:
    any of ($encrptlib, $encrptlib1, $encrptlib2, $encrptlib3) and $encrptcustom
}
rule apkprotect_b: packer
{
  meta:
    description = "APKProtect"
  strings:
    $key = "apkprotect.com/key.dat"
    $dir = "apkprotect.com/"
    $lib = "libAPKProtect.so"
  condition:
    ($key or $dir or $lib)
}
rule kiro_c: packer
{
  meta:
    description = "Kiro"
  strings:
    $kiro_lib = "libkiroro.so"
    $sbox = "assets/sbox"
  condition:
    $kiro_lib and $sbox
}
rule qihoo360_d: packer
{
  meta:
    description = "Qihoo 360"
  strings:
    $a = "libprotectClass.so"
  condition:
    $a and
    not kiro
}
rule ijiami_d: packer
{
  meta:
    description = "Ijiami"
  strings:
    $old_dat = "assets/ijiami.dat"
    $new_ajm = "ijiami.ajm"
    $ijm_lib = "assets/ijm_lib/"
  condition:
    ($old_dat or $new_ajm or $ijm_lib)
}
rule medusah_c: packer
{
  meta:
    description = "Medusah"
    url = "https://medusah.com/"
  strings:
    $lib = "libmd.so"
  condition:
    $lib
}
rule medusah_d: packer
{
  meta:
    description = "Medusah"
    url = "https://medusah.com/"
  strings:
    $lib = "libmd.so"
  condition:
    $lib
}
rule medusah_appsolid_c: packer
{
  meta:
    description = "Medusah (AppSolid)"
    url = "https://appsolid.co/"
  strings:
    $encrypted_dex = "assets/high_resolution.png"
  condition:
    $encrypted_dex and not medusah
}
rule kony_c: packer
{
  meta:
    description = "Kony"
	  url = "http://www.kony.com/"
  strings:
    $lib = "libkonyjsvm.so"
    $decrypt_keys = "assets/application.properties"
    $encrypted_js = "assets/js/startup.js"
  condition:
    $lib and $decrypt_keys and $encrypted_js
}
rule yidun_b: packer
{
  meta:
    description = "yidun"
	  url = "https://dun.163.com/product/app-protect"
  strings:
    $anti_trick = "Lcom/_" // Class path of anti-trick
    $entry_point = "Lcom/netease/nis/wrapper/Entry"
    $jni_func = "Lcom/netease/nis/wrapper/MyJni"
    $lib = "libnesec.so"
  condition:
    (#lib > 1) or ($anti_trick and $entry_point and $jni_func)
}
rule approov_c: packer
{
  meta:
    description = "Aproov"
	  url = "https://www.approov.io/"
  strings:
    $lib = "libapproov.so"
    $sdk_config = "assets/cbconfig.JSON"
  condition:
    $lib and $sdk_config
}
rule pangxie_d: packer
{
  meta:
    description = "PangXie"
    example = "ea70a5b3f7996e9bfea2d5d99693195fdb9ce86385b7116fd08be84032d43d2c"
  strings:
    $lib = "libnsecure.so"
  condition:
    $lib
}
rule baidu_d: packer
{
  meta:
    description = "Baidu"
  strings:
    $lib = "libbaiduprotect.so"
    $encrypted = "baiduprotect1.jar"
  condition:
    ($lib or $encrypted)
}
rule alibaba_d: packer
{
  meta:
    description = "Alibaba"
  strings:
    $lib = "libmobisec.so"
  condition:
    $lib
}
rule tencent_b: packer
{
  meta:
    description = "Tencent"
  strings:
    $decryptor_lib = "lib/armeabi/libshell.so"
    $zip_lib = "lib/armeabi/libmobisecy.so"
    $classpath = "com/tencent/StubShell"
    $mix_dex = "/mix.dex"
  condition:
    ($classpath or $decryptor_lib or $zip_lib or $mix_dex)
}
rule nqshield_c: packer
{
  meta:
    description = "NQ Shield"
  strings:
    $lib = "libnqshield.so"
    $lib_sec1 = "nqshield"
    $lib_sec2 = "nqshell"
  condition:
    any of ($lib, $lib_sec1, $lib_sec2)
}
rule app_fortify_c: packer
{
  meta:
    description = "App Fortify"
  strings:
    $lib = "libNSaferOnly.so"
  condition:
    $lib
}
rule liapp_b: packer
{
  meta:
    description = "LIAPP"
  strings:
    $dir = "/LIAPPEgg"
    $lib = "LIAPPClient.sc"
  condition:
    any of ($dir, $lib)
}
rule bangcle_b: packer
{
  meta:
    description = "Bangcle"
  strings:
    $main_lib = "libsecexe.so"
    $second_lib = "libsecmain.so"
    $container = "assets/bangcleplugin/container.dex"
    $encrypted_jar = "bangcleclasses.jar"
    $encrypted_jar2 = "bangcle_classes.jar"
  condition:
    any of ($main_lib, $second_lib, $container, $encrypted_jar, $encrypted_jar2)
}
rule CNProtect_dex_a: protector
{
  meta:
    description = "CNProtect (anti-disassemble)"
    example = "5bf6887871ce5f00348b1ec6886f9dd10b5f3f5b85d3d628cf21116548a3b37d"
  strings:
    $code_segment = {
	  02 00 01 00 00 00 00 00 ?? ?? ?? ?? 11 00 00 00 00 (1? | 2? | 3? | 4? | 5? | 6? | 7? | 8? | 9? | a? | b? | c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7)
    }
  condition:
    $code_segment
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
rule Leecher_A_a
{
    condition:
        androguard.certificate.sha1("B24C060D41260C0C563FEAC28E6CA1874A14B192")
}
rule Service_a:Gogle
{
	condition:
		androguard.service("com.module.yqural.gogle")
}
rule koodous_fa: official
{
	meta:
		description = "Ruleset to detect kwetza tool to inject malicious code in Android applications."
		url = "https://github.com/sensepost/kwetza"
	strings:
		$a = "maakDieStageVanTcp"wide ascii
		$b = "payloadStart"wide ascii
		$c = "leesEnLoopDieDing"wide ascii
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
rule Raxir_a: ccm
{
        meta:
        description = "This rule was produced by CreateYaraRule and CommonCode, it detects RAXIR string decription routine"
        author = "_hugo_gonzalez_ "
		sample = "07278c56973d609caa5f9eb2393d9b1eb41964d24e7e9e7a7e7f9fdfb2bb4c31"
        strings :
		$S_8_12_72 = { 12 01 d8 00 ?? ?? 6e 10 ?? ?? ?? 00 0c 04 21 45 01 02 01 10 32 50 11 00 49 03 04 00 dd 06 02 5f b7 36 d8 03 02 ?? d8 02 00 01 8e 66 50 06 04 00 01 20 01 32 28 f0 71 30 ?? ?? 14 05 0c 00 6e 10 ?? ?? 00 00 0c 00 11 00 }
    condition:
        all of them
}
rule spynote_a: RAT
{
	meta:
		sample = "bd3269ec0d8e0fc2fbb8f01584a7f5de320a49dfb6a8cc60119ad00c7c0356a5"
	condition:
		androguard.package_name("com.spynote.software.stubspynote")
}
rule RuMMS_a {
	strings:
		$ = "5.45.78.20"
	condition:
		all of them
}
rule koodous_ga: official
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
rule exaspy_a: OnlyParsersCode
{
	meta:
		description = "This rule detects exaspy, its focused only on custom code to 'Parse' information from phone"
		sample = "b9d37ce509d37ade6cb064ff41e6de99fcf686fcea70ae355f76018896eaf508"
		author = "_hugo_gonzalez_ "
	strings:
		$S_4_1266 = { 12 11 38 04 0b 00 54 32 ?? ?? 6e 20 ?? ?? 24 00 0a 02 38 02 03 00 0f 01 38 05 0a 00 54 32 ?? ?? 6e 20 ?? ?? 25 00 0a 02 39 02 f7 ff 12 01 28 f4 0d 00 62 01 ?? ?? 1a 02 ?? ?? 71 30 ?? ?? 21 00 28 f6 }
		$S_4_5476 = { 54 20 ?? ?? 39 00 21 00 70 10 ?? ?? 02 00 0c 00 5b 20 ?? ?? 54 20 ?? ?? 39 00 17 00 54 20 ?? ?? 71 10 ?? ?? 00 00 0c 00 6e 10 ?? ?? 02 00 0c 01 6e 20 ?? ?? 10 00 22 00 ?? ?? 1a 01 ?? ?? 70 20 ?? ?? 10 00 27 00 1a 00 ?? ?? 11 00 }
		$S_4_5472 = { 54 20 ?? ?? 39 00 10 00 54 20 ?? ?? 1a 01 ?? ?? 71 20 ?? ?? 10 00 0a 00 38 00 09 00 1a 00 ?? ?? 5b 20 ?? ?? 54 20 ?? ?? 11 00 54 20 ?? ?? 1a 01 ?? ?? 71 20 ?? ?? 10 00 0a 00 38 00 f5 ff 1a 00 ?? ?? 5b 20 ?? ?? 28 ef }
		$S_4_7072 = { 70 10 ?? ?? 03 00 6e 10 ?? ?? 03 00 0c 00 71 10 ?? ?? 00 00 0c 00 5b 30 ?? ?? 12 20 23 00 ?? ?? 12 01 1a 02 ?? ?? 4d 02 00 01 12 11 1a 02 ?? ?? 4d 02 00 01 5b 30 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 5b 30 ?? ?? 0e 00 }
		$S_4_5470 = { 54 42 ?? ?? 38 02 20 00 54 42 ?? ?? 6e 20 ?? ?? 54 00 0c 03 6e 20 ?? ?? 32 00 0c 00 1f 00 ?? ?? 38 00 12 00 6e 10 ?? ?? 00 00 0c 01 71 10 ?? ?? 01 00 0a 02 39 02 08 00 54 42 ?? ?? 71 30 ?? ?? 12 01 0c 06 11 06 }
		$S_4_1a326 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_7050 = { 70 10 ?? ?? 01 00 6e 10 ?? ?? 01 00 0c 00 71 10 ?? ?? 00 00 0c 00 5b 10 ?? ?? 1a 00 ?? ?? 5b 10 ?? ?? 5b 12 ?? ?? 5b 13 ?? ?? 71 20 ?? ?? 12 00 0e 00 }
		$S_4_12176 = { 12 0a 12 08 54 b0 ?? ?? 1a 01 ?? ?? 12 12 23 22 ?? ?? 12 03 1a 04 ?? ?? 4d 04 02 03 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? c3 00 0c 03 6e 10 ?? ?? 03 00 0c 03 12 04 12 05 12 06 12 07 74 08 ?? ?? 00 00 0c 08 38 08 13 00 72 10 ?? 02 08 00 0a 00 38 00 0d 00 12 00 72 20 ?? 02 08 00 0c 00 38 08 05 00 72 10 ?? 02 08 00 11 00 38 08 05 00 72 10 ?? 02 08 00 07 a0 28 f9 0d 09 62 00 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 09 38 08 f6 ff 72 10 ?? 02 08 00 28 f1 0d 00 38 08 05 00 72 10 ?? 02 08 00 27 00 }
		$S_4_08170 = { 08 00 11 00 52 02 ?? ?? 08 00 12 00 72 20 ?? 02 20 00 0c 05 08 00 11 00 52 02 ?? ?? 08 00 12 00 72 20 ?? 02 20 00 0c 06 08 00 11 00 52 02 ?? ?? 08 00 12 00 72 20 ?? 02 20 00 0c 07 08 00 11 00 52 02 ?? ?? 08 00 12 00 72 20 ?? 02 20 00 0b 08 08 00 11 00 52 02 ?? ?? 08 00 12 00 72 20 ?? 02 20 00 0a 02 08 00 11 00 70 20 ?? ?? 20 00 0a 0a 22 03 ?? ?? 08 00 11 00 54 04 ?? ?? 76 08 ?? ?? 03 00 11 03 0d 0f 08 00 11 00 54 0b ?? ?? 08 00 11 00 54 0c ?? ?? 1a 0d ?? ?? 12 0e 62 10 ?? ?? 77 06 ?? ?? 0b 00 12 03 28 ed }
		$S_4_2248 = { 22 00 ?? ?? 70 10 ?? ?? 00 00 60 01 ?? ?? 72 20 ?? 02 13 00 0c 01 6e 20 ?? ?? 10 00 60 01 ?? ?? 72 20 ?? 02 13 00 0c 01 6e 20 ?? ?? 10 00 11 00 }
		$S_4_39122 = { 39 04 04 00 12 00 11 00 12 00 1a 01 ?? ?? 6e 20 ?? ?? 14 00 0a 01 38 01 1c 00 1a 00 ?? 05 38 00 f4 ff 38 05 f2 ff 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 20 ?? ?? 01 00 0c 01 1a 02 ?? ?? 6e 20 ?? ?? 21 00 0c 01 6e 10 ?? ?? 01 00 0c 00 28 dd 1a 01 ?? ?? 6e 20 ?? ?? 14 00 0a 01 38 01 05 00 1a 00 ?? 05 28 de 1a 01 ?? ?? 6e 20 ?? ?? 14 00 0a 01 38 01 d7 ff 1a 00 ?? 05 28 d3 }
		$S_4_12272 = { 12 08 54 b0 ?? ?? 1a 01 ?? ?? 12 22 23 22 ?? ?? 12 03 1a 04 ?? ?? 4d 04 02 03 12 13 1a 04 ?? ?? 4d 04 02 03 1a 03 ?? ?? 12 14 23 44 ?? ?? 12 05 6e 10 ?? ?? 0d 00 0c 06 4d 06 04 05 12 05 12 06 12 07 74 08 ?? ?? 00 00 0c 08 1a 09 00 00 38 08 2a 00 72 10 ?? 02 08 00 0a 00 38 00 24 00 1a 00 ?? ?? 72 20 ?? 02 08 00 0a 00 72 20 ?? 02 08 00 0c 09 38 09 08 00 6e 10 ?? ?? 09 00 0a 00 38 00 0c 00 1a 00 ?? ?? 72 20 ?? 02 08 00 0a 00 72 20 ?? 02 08 00 0c 09 72 10 ?? 02 08 00 0a 00 39 00 e0 ff 6e 20 ?? ?? 9d 00 38 08 05 00 72 10 ?? 02 08 00 0e 00 0d 0a 54 b0 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 0c 01 6e 10 ?? ?? 0d 00 0c 02 71 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 21 00 0c 01 6e 10 ?? ?? 01 00 0c 01 71 30 ?? ?? 10 0a 38 08 de ff 72 10 ?? 02 08 00 28 d9 0d 00 38 08 05 00 72 10 ?? 02 08 00 27 00 }
		$S_4_22184 = { 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 04 6e 20 ?? ?? 43 00 0c 03 1a 04 ?? 05 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 02 12 13 71 10 ?? ?? 03 00 0c 00 1a 03 ?? ?? 12 14 71 40 ?? ?? 02 43 0a 03 39 03 14 00 22 03 ?? ?? 1a 04 ?? ?? 70 20 ?? ?? 43 00 27 03 0d 01 62 03 ?? ?? 1a 04 ?? ?? 71 30 ?? ?? 43 01 12 03 11 03 22 03 ?? ?? 22 04 ?? ?? 70 10 ?? ?? 04 00 6e 20 ?? ?? 04 00 0c 04 1a 05 ?? ?? 6e 20 ?? ?? 54 00 0c 04 1a 05 ?? ?? 6e 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0c 04 70 20 ?? ?? 43 00 70 20 ?? ?? 36 00 0c 03 28 dd }
		$S_4_12274 = { 12 05 6e 10 ?? ?? 0c 00 0c 03 1a 02 00 00 39 03 13 00 22 06 ?? ?? 1a 07 ?? ?? 70 20 ?? ?? 76 00 27 06 0d 00 54 96 ?? ?? 1a 07 ?? ?? 71 30 ?? ?? 76 00 0f 05 1a 06 ?? ?? 6e 20 ?? ?? 63 00 0a 06 39 06 f9 ff 1a 06 ?? ?? 6e 20 ?? ?? 63 00 0a 06 38 06 40 00 6e 10 ?? ?? 0c 00 0c 04 71 10 ?? 05 04 00 0c 06 6e 10 ?? 05 06 00 0c 02 6e 10 ?? ?? 0c 00 0c 06 6e 20 ?? ?? 6c 00 62 06 ?? ?? 6e 20 ?? ?? 6c 00 12 06 71 20 ?? ?? 62 00 0a 06 39 06 3d 00 22 06 ?? ?? 22 07 ?? ?? 70 10 ?? ?? 07 00 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 1a 08 ?? ?? 71 20 ?? ?? 82 00 0c 08 6e 20 ?? ?? 87 00 0c 07 6e 10 ?? ?? 07 00 0c 07 70 20 ?? ?? 76 00 27 06 1a 06 ?? ?? 6e 20 ?? ?? 63 00 0a 06 38 06 d4 ff 6e 10 ?? ?? 0c 00 0c 01 54 96 ?? ?? 6e 10 ?? ?? 09 00 0c 07 6e 30 ?? ?? 76 01 0c 02 62 06 ?? ?? 6e 20 ?? ?? 6c 00 28 bf 6e 5d ?? ?? a9 2c 12 15 28 91 }
		$S_4_6f28 = { 6f 20 ?? ?? 32 00 0c 00 1f 00 ?? ?? 38 00 07 00 62 01 ?? ?? 6e 20 ?? ?? 10 00 11 00 }
		$S_4_6f26 = { 6f 10 ?? ?? 01 00 1a 00 ?? ?? 71 10 ?? ?? 00 00 0c 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_6e38 = { 6e 10 ?? ?? 03 00 0c 00 71 10 ?? ?? 00 00 0a 01 39 01 09 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0a 01 0f 01 12 01 28 fe }
		$S_8_5464 = { 54 41 ?? ?? 71 30 ?? ?? 41 05 54 41 ?? ?? 71 10 ?? ?? 01 00 0c 00 6e 10 ?? ?? 04 00 0c 01 6e 20 ?? ?? 10 00 0a 01 5c 41 ?? ?? 6e 10 ?? ?? 04 00 0c 01 6e 20 ?? ?? 10 00 0b 02 5a 42 ?? ?? 0e 00 }
		$S_4_1a68 = { 1a 04 ?? 00 6e 20 ?? ?? 47 00 0c 03 21 34 23 40 ?? ?? 12 02 21 04 35 42 16 00 46 04 03 02 70 20 ?? ?? 46 00 0c 04 4d 04 00 02 d8 02 02 01 28 f3 0d 01 62 04 ?? ?? 1a 05 ?? ?? 71 30 ?? ?? 54 01 12 00 11 00 }
		$S_4_70164 = { 70 20 ?? ?? ca 00 0c 07 38 07 4c 00 12 08 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 71 00 ?? ?? 00 00 0b 02 6e 30 ?? ?? 20 03 0c 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 6e 20 ?? ?? c0 00 0c 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 6e 10 ?? ?? 00 00 0c 06 71 10 ?? ?? 06 00 0c 00 71 10 ?? ?? 00 00 0c 09 22 08 ?? ?? 70 20 ?? ?? 98 00 71 20 ?? ?? 87 00 6e 20 ?? ?? 8b 00 12 10 0f 00 0d 04 54 a0 ?? ?? 54 a1 ?? ?? 1a 02 ?? ?? 12 03 62 05 ?? ?? 77 06 ?? ?? 00 00 12 00 28 f1 }
		$S_4_1a146 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_12268 = { 12 03 1d 06 12 00 12 02 6f 10 ?? ?? 06 00 0a 04 38 04 51 00 1a 04 ?? ?? 6e 20 ?? ?? 46 00 0c 04 5b 64 ?? ?? 1a 04 ?? ?? 6e 20 ?? ?? 46 00 0c 00 38 00 1c 00 22 04 ?? ?? 54 65 ?? ?? 70 30 ?? ?? 54 00 5b 64 ?? ?? 54 64 ?? ?? 39 04 0a 00 54 64 ?? ?? 6e 10 ?? ?? 04 00 0c 04 5b 64 ?? ?? 54 64 ?? ?? 6e 10 ?? ?? 04 00 1a 04 ?? ?? 6e 20 ?? ?? 46 00 0c 02 38 02 0c 00 54 64 ?? ?? 39 04 08 00 70 20 ?? ?? 26 00 0c 04 5b 64 ?? ?? 54 64 ?? ?? 38 04 05 00 38 00 03 00 12 13 38 00 05 00 6e 10 ?? ?? 00 00 38 02 05 00 6e 10 ?? ?? 02 00 1e 06 0f 03 38 00 05 00 6e 10 ?? ?? 00 00 38 02 f9 ff 6e 10 ?? ?? 02 00 28 f4 0d 03 1e 06 27 03 0d 01 62 04 ?? ?? 1a 05 ?? ?? 71 30 ?? ?? 54 01 38 00 05 00 6e 10 ?? ?? 00 00 38 02 e3 ff 6e 10 ?? ?? 02 00 28 de 0d 03 38 00 05 00 6e 10 ?? ?? 00 00 38 02 05 00 6e 10 ?? ?? 02 00 27 03 }
		$S_4_12302 = { 12 0e 1a 09 ?? ?? 1a 0a ?? ?? 1a 0b ?? ?? 08 00 11 00 54 01 ?? ?? 1a 02 ?? ?? 12 33 23 33 ?? ?? 12 04 1a 05 ?? ?? 4d 05 03 04 12 14 1a 05 ?? ?? 4d 05 03 04 12 24 1a 05 ?? ?? 4d 05 03 04 22 04 ?? ?? 70 10 ?? ?? 04 00 1a 05 ?? ?? 6e 20 ?? ?? 54 00 0c 04 08 00 12 00 6e 20 ?? ?? 04 00 0c 04 1a 05 ?? ?? 6e 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0c 04 12 05 12 06 12 07 12 08 74 08 ?? ?? 01 00 0c 0e 38 0e 39 00 72 10 ?? 02 0e 00 0a 01 38 01 33 00 22 0d ?? ?? 08 00 12 00 70 20 ?? ?? 0d 00 1a 01 ?? ?? 72 20 ?? 02 1e 00 0a 01 72 20 ?? 02 1e 00 0a 0c 12 21 33 1c 1c 00 13 10 01 00 02 00 10 00 6e 20 ?? ?? 0d 00 1a 01 ?? ?? 72 20 ?? 02 1e 00 0a 01 72 20 ?? 02 1e 00 0c 01 6e 20 ?? ?? 1d 00 38 0e 05 00 72 10 ?? 02 0e 00 11 0d 13 10 00 00 28 e6 38 0e 05 00 72 10 ?? 02 0e 00 12 0d 28 f6 0d 0f 62 01 ?? ?? 1a 02 ?? ?? 71 30 ?? ?? 21 0f 38 0e f6 ff 72 10 ?? 02 0e 00 28 f1 0d 01 38 0e 05 00 72 10 ?? 02 0e 00 27 01 }
		$S_8_2256 = { 22 00 ?? ?? 70 10 ?? ?? 00 00 71 00 ?? ?? 00 00 0a 01 72 20 ?? 02 13 00 0c 01 6e 20 ?? ?? 10 00 71 00 ?? ?? 00 00 0a 01 72 20 ?? 02 13 00 0c 01 6e 20 ?? ?? 10 00 11 00 }
		$S_4_1a92 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_2252 = { 22 01 ?? ?? 54 32 ?? ?? 6e 10 ?? ?? 02 00 0c 02 70 20 ?? ?? 21 00 11 01 0d 00 54 31 ?? ?? 1a 02 ?? ?? 71 30 ?? ?? 21 00 22 01 ?? ?? 70 10 ?? ?? 01 00 28 f2 }
		$S_4_1d64 = { 1d 01 6f 10 ?? ?? 01 00 54 10 ?? ?? 71 10 ?? ?? 00 00 1a 00 ?? ?? 71 10 ?? ?? 00 00 0c 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 71 10 ?? ?? 00 00 0c 00 71 10 ?? ?? 00 00 1e 01 0e 00 0d 00 1e 01 27 00 }
		$S_4_12428 = { 12 0d 12 0a 54 e0 ?? ?? 39 00 18 00 22 00 ?? ?? 1a 01 ?? ?? 70 20 ?? ?? 10 00 27 00 0d 0b 54 e0 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 0b 38 0a 05 00 72 10 ?? 02 0a 00 11 0d 39 0f 11 00 22 00 ?? ?? 1a 01 ?? ?? 70 20 ?? ?? 10 00 27 00 0d 00 38 0a 05 00 72 10 ?? 02 0a 00 27 00 22 09 ?? ?? 70 10 ?? ?? 09 00 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 6e 20 ?? ?? f0 00 0c 00 1a 01 ?? 02 6e 20 ?? ?? 10 00 0c 00 6e 10 ?? ?? 00 00 0c 00 6e 20 ?? ?? 09 00 54 e0 ?? ?? 6e 10 ?? ?? 0e 00 0c 01 12 52 23 22 ?? ?? 12 03 1a 04 ?? ?? 4d 04 02 03 12 13 1a 04 ?? ?? 4d 04 02 03 12 23 1a 04 ?? ?? 4d 04 02 03 12 33 1a 04 ?? ?? 4d 04 02 03 12 43 1a 04 ?? ?? 4d 04 02 03 6e 10 ?? ?? 09 00 0c 03 6e 10 ?? ?? 09 00 0c 04 12 05 12 06 1a 07 ?? ?? 12 08 74 09 ?? ?? 00 00 0c 0a 6e 20 ?? ?? ae 00 72 10 ?? 02 0a 00 0a 00 38 00 47 00 22 0c ?? ?? 70 10 ?? ?? 0c 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0a 00 0c 00 6e 20 ?? ?? 0c 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0a 00 0c 00 6e 20 ?? ?? 0c 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0a 00 0c 00 6e 20 ?? ?? 0c 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0a 00 0b 00 71 20 ?? ?? 10 00 0c 00 6e 20 ?? ?? 0c 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0a 00 0b 00 71 20 ?? ?? 10 00 0c 00 6e 20 ?? ?? 0c 00 07 cd 38 0a 4c ff 72 10 ?? 02 0a 00 29 00 47 ff }
		$S_4_22390 = { 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 02 00 00 54 a7 ?? ?? 22 08 ?? ?? 70 10 ?? ?? 08 00 1a 09 ?? ?? 6e 20 ?? ?? 98 00 0c 08 72 10 ?? 02 0b 00 0a 09 6e 20 ?? ?? 98 00 0c 08 6e 10 ?? ?? 08 00 0c 08 71 20 ?? ?? 87 00 72 10 ?? 02 0b 00 0a 07 38 07 98 00 12 04 12 05 52 a7 ?? ?? 72 20 ?? 02 7b 00 0c 04 52 a7 ?? ?? 72 20 ?? 02 7b 00 0c 05 54 a7 ?? ?? 22 08 ?? ?? 70 10 ?? ?? 08 00 1a 09 ?? ?? 6e 20 ?? ?? 98 00 0c 08 71 10 ?? ?? 05 00 0c 09 6e 20 ?? ?? 98 00 0c 08 6e 10 ?? ?? 08 00 0c 08 71 20 ?? ?? 87 00 39 05 2a 00 22 07 ?? ?? 1a 08 ?? ?? 70 20 ?? ?? 87 00 27 07 0d 01 54 a7 ?? ?? 22 08 ?? ?? 70 10 ?? ?? 08 00 1a 09 ?? ?? 6e 20 ?? ?? 98 00 0c 08 1a 09 ?? ?? 71 20 ?? ?? 95 00 0c 09 6e 20 ?? ?? 98 00 0c 08 6e 10 ?? ?? 08 00 0c 08 71 30 ?? ?? 87 01 28 a7 1a 07 ?? ?? 6e 20 ?? ?? 75 00 0a 07 38 07 33 00 1a 06 00 00 52 a7 ?? ?? 72 20 ?? 02 7b 00 0c 00 38 00 22 00 70 20 ?? ?? 4a 00 0c 06 22 07 ?? ?? 70 10 ?? ?? 07 00 6e 20 ?? ?? 27 00 0c 07 1a 08 ?? 00 6e 20 ?? ?? 87 00 0c 07 6e 20 ?? ?? 67 00 0c 07 6e 10 ?? ?? 07 00 0c 02 70 30 ?? ?? 3a 04 29 00 76 ff 52 a7 ?? ?? 72 20 ?? 02 7b 00 0c 06 28 de 1a 07 ?? ?? 6e 20 ?? ?? 75 00 0a 07 38 07 ee ff 28 ec 6e 20 ?? ?? 23 00 11 03 }
		$S_4_22158 = { 22 04 ?? ?? 70 10 ?? ?? 04 00 1a 06 ?? ?? 12 17 71 20 ?? ?? 76 00 0c 05 39 05 14 00 22 06 ?? ?? 1a 07 ?? ?? 70 20 ?? ?? 76 00 27 06 0d 01 62 06 ?? ?? 1a 07 ?? ?? 71 30 ?? ?? 76 01 12 06 11 06 22 00 ?? ?? 22 06 ?? ?? 70 20 ?? ?? 56 00 70 20 ?? ?? 60 00 6e 10 ?? ?? 00 00 0c 03 38 03 18 00 1a 06 ?? ?? 6e 20 ?? ?? 63 00 0a 06 38 06 0b 00 71 10 ?? ?? 00 00 0c 02 38 02 05 00 72 20 ?? ?? 24 00 6e 10 ?? ?? 00 00 0c 03 28 e9 6e 10 ?? ?? 00 00 28 d5 0d 06 6e 10 ?? ?? 00 00 27 06 }
		$S_4_22402 = { 22 09 ?? ?? 70 10 ?? ?? 09 00 12 0b 54 e0 ?? ?? 39 00 18 00 22 00 ?? ?? 1a 01 ?? ?? 70 20 ?? ?? 10 00 27 00 0d 0c 54 e0 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 0c 38 0b 05 00 72 10 ?? 02 0b 00 11 09 22 0a ?? ?? 70 10 ?? ?? 0a 00 54 e0 ?? ?? 71 30 ?? ?? e0 0a 70 20 ?? ?? ae 00 54 e0 ?? ?? 6e 10 ?? ?? 0e 00 0c 01 12 52 23 22 ?? ?? 12 03 1a 04 ?? ?? 4d 04 02 03 12 13 1a 04 ?? ?? 4d 04 02 03 12 23 1a 04 ?? ?? 4d 04 02 03 12 33 1a 04 ?? ?? 4d 04 02 03 12 43 1a 04 ?? ?? 4d 04 02 03 6e 10 ?? ?? 0a 00 0c 03 6e 10 ?? ?? 0a 00 0c 04 12 05 12 06 1a 07 ?? ?? 12 08 74 09 ?? ?? 00 00 0c 0b 6e 20 ?? ?? be 00 39 0b 11 00 22 00 ?? ?? 1a 01 ?? ?? 70 20 ?? ?? 10 00 27 00 0d 00 38 0b 05 00 72 10 ?? 02 0b 00 27 00 72 10 ?? 02 0b 00 0a 00 38 00 4a 00 22 0d ?? ?? 70 10 ?? ?? 0d 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0b 00 0c 00 6e 20 ?? ?? 0d 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0b 00 0c 00 6e 20 ?? ?? 0d 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0b 00 0c 00 6e 20 ?? ?? 0d 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0b 00 0b 00 71 20 ?? ?? 10 00 0c 00 6e 20 ?? ?? 0d 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0b 00 0b 00 71 20 ?? ?? 10 00 0c 00 6e 20 ?? ?? 0d 00 72 20 ?? ?? d9 00 28 b3 38 0b 5d ff 72 10 ?? 02 0b 00 29 00 58 ff }
		$S_4_6266 = { 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 0e 00 }
		$S_4_22270 = { 22 01 ?? ?? 70 10 ?? ?? 01 00 6e 10 ?? ?? 06 00 0c 02 38 02 6e 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0a 03 39 03 66 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0a 03 38 03 16 00 71 10 ?? ?? 02 00 0c 03 1a 04 ?? 02 1a 05 00 00 6e 30 ?? ?? 43 05 0c 03 6e 20 ?? ?? 31 00 6e 10 ?? ?? 06 00 0c 02 28 db 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0a 03 38 03 1c 00 71 10 ?? ?? 02 00 0c 03 1a 04 ?? 02 1a 05 00 00 6e 30 ?? ?? 43 05 0c 03 6e 20 ?? ?? 31 00 28 e4 0d 00 62 03 ?? ?? 1a 04 ?? ?? 71 30 ?? ?? 43 00 12 01 11 01 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0a 03 38 03 0a 00 71 10 ?? ?? 02 00 0c 03 6e 20 ?? ?? 31 00 28 ca 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0a 03 38 03 c3 ff 71 10 ?? ?? 02 00 0c 03 1a 04 ?? 06 6e 20 ?? ?? 43 00 0a 03 6e 20 ?? ?? 31 00 28 b4 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0a 03 39 03 d3 ff 22 03 ?? ?? 1a 04 ?? ?? 70 20 ?? ?? 43 00 27 03 }
		$S_4_12158 = { 12 09 12 08 54 b0 ?? ?? 38 00 30 00 54 b0 ?? ?? 6e 10 ?? ?? 0b 00 0c 01 12 12 23 22 ?? ?? 12 03 1a 04 ?? ?? 4d 04 02 03 1a 03 ?? ?? 12 04 12 05 12 06 12 07 74 08 ?? ?? 00 00 0c 08 72 10 ?? 02 08 00 0a 00 38 00 12 00 1a 00 ?? ?? 72 20 ?? 02 08 00 0a 00 72 20 ?? 02 08 00 0c 09 38 08 05 00 72 10 ?? 02 08 00 11 09 38 08 ff ff 72 10 ?? 02 08 00 28 fa 0d 0a 54 b0 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 0a 38 08 f1 ff 72 10 ?? 02 08 00 28 ec 0d 00 38 08 05 00 72 10 ?? 02 08 00 27 00 }
		$S_4_39246 = { 39 0a 13 00 22 04 ?? ?? 1a 05 ?? ?? 70 20 ?? ?? 54 00 27 04 0d 02 62 04 ?? ?? 1a 05 ?? ?? 71 30 ?? ?? 54 02 0e 00 6e 10 ?? ?? 0a 00 0c 04 6e 10 ?? ?? 04 00 0b 04 71 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0b 04 53 86 ?? ?? 71 40 ?? ?? 54 76 0a 04 38 04 e9 ff 22 04 ?? ?? 70 10 ?? ?? 04 00 6e 10 ?? ?? 0a 00 0c 05 6e 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 0a 00 0c 05 6e 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0c 00 62 04 ?? ?? 22 05 ?? ?? 70 10 ?? ?? 05 00 1a 06 ?? ?? 6e 20 ?? ?? 65 00 0c 05 6e 20 ?? ?? 05 00 0c 05 6e 10 ?? ?? 05 00 0c 05 71 20 ?? ?? 54 00 6e 10 ?? ?? 0a 00 0c 03 71 10 ?? 05 03 00 0c 04 6e 10 ?? 05 04 00 0c 03 12 14 71 30 ?? ?? 03 04 0c 01 39 01 0a 00 22 04 ?? ?? 1a 05 ?? ?? 70 20 ?? ?? 54 00 27 04 6e 20 ?? ?? 19 00 28 98 }
		$S_8_1250 = { 12 f0 33 03 04 00 12 00 11 00 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 6e 20 ?? ?? 30 00 0c 00 6e 10 ?? ?? 00 00 0c 00 28 ec }
		$S_4_12154 = { 12 09 12 08 22 06 ?? ?? 70 10 ?? ?? 06 00 1a 00 ?? ?? 6e 30 ?? ?? 06 0b 1a 00 ?? ?? 1a 01 ?? 04 6e 30 ?? ?? 06 01 54 a0 ?? ?? 6e 10 ?? ?? 0a 00 0c 01 6e 10 ?? ?? 0a 00 0c 02 6e 10 ?? ?? 06 00 0c 03 6e 10 ?? ?? 06 00 0c 04 12 05 74 06 ?? 01 00 00 0c 08 6e 20 ?? ?? 8a 00 70 20 ?? ?? 8a 00 0c 00 38 08 05 00 72 10 ?? 02 08 00 11 00 0d 07 54 a0 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 07 38 08 05 00 72 10 ?? 02 08 00 07 90 28 f1 0d 00 38 08 05 00 72 10 ?? 02 08 00 27 00 }
		$S_4_2260 = { 22 00 ?? ?? 70 10 ?? ?? 00 00 6e 10 ?? ?? 02 00 0c 01 71 10 ?? ?? 01 00 0c 01 6e 20 ?? ?? 10 00 0c 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 6e 10 ?? ?? 00 00 0c 00 5b 20 ?? ?? 0e 00 }
		$S_4_22242 = { 22 02 ?? ?? 70 10 ?? ?? 02 00 71 00 ?? ?? 00 00 0a 03 72 20 ?? 02 37 00 0c 03 6e 20 ?? ?? 32 00 71 00 ?? ?? 00 00 0a 03 72 20 ?? 02 37 00 0b 04 6e 30 ?? ?? 42 05 71 00 ?? ?? 00 00 0a 03 72 20 ?? 02 37 00 0c 03 6e 20 ?? ?? 32 00 71 00 ?? ?? 00 00 0a 03 72 20 ?? 02 37 00 0c 01 70 20 ?? ?? 16 00 0c 03 6e 20 ?? ?? 32 00 71 00 ?? ?? 00 00 0a 03 72 20 ?? 02 37 00 0c 03 70 20 ?? ?? 36 00 0c 03 6e 20 ?? ?? 32 00 71 00 ?? ?? 00 00 0a 03 72 20 ?? 02 37 00 0c 03 70 20 ?? ?? 36 00 0c 03 6e 20 ?? ?? 32 00 71 00 ?? ?? 00 00 0a 03 72 20 ?? 02 37 00 0c 03 70 20 ?? ?? 36 00 0c 03 6e 20 ?? ?? 32 00 70 20 ?? ?? 76 00 0a 03 6e 20 ?? ?? 32 00 70 30 ?? ?? 76 02 70 30 ?? ?? 76 02 11 02 0d 00 54 63 ?? ?? 1a 04 ?? ?? 71 30 ?? ?? 43 00 28 f7 }
		$S_4_12318 = { 12 09 38 10 70 00 1a 02 ?? ?? 12 11 23 13 ?? ?? 12 01 1a 04 ?? ?? 4d 04 03 01 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 04 ?? ?? 6e 20 ?? ?? 41 00 0c 01 08 00 11 00 6e 20 ?? ?? 01 00 0c 01 1a 04 ?? ?? 6e 20 ?? ?? 41 00 0c 01 6e 10 ?? ?? 01 00 0c 04 12 05 12 06 12 07 12 08 08 01 10 00 74 08 ?? ?? 01 00 0c 09 72 10 ?? 02 09 00 0a 01 38 01 3b 00 1a 01 ?? ?? 72 20 ?? 02 19 00 0a 01 72 20 ?? 02 19 00 0c 0e 22 0c ?? ?? 70 20 ?? ?? ec 00 6e 10 ?? ?? 0c 00 0a 0d 6e 10 ?? ?? 0c 00 0a 01 23 1f ?? ?? 12 0b 35 db 11 00 6e 20 ?? ?? bc 00 0c 01 1a 02 ?? ?? 6e 20 ?? ?? 21 00 0c 01 4d 01 0f 0b d8 0b 0b 01 28 f0 3d 0d 0e 00 1a 01 ?? ?? 71 20 ?? ?? f1 00 0c 12 38 09 05 00 72 10 ?? 02 09 00 11 12 38 09 ff ff 72 10 ?? 02 09 00 28 fa 0d 0a 62 01 ?? ?? 22 02 ?? ?? 70 10 ?? ?? 02 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0c 02 08 00 11 00 6e 20 ?? ?? 02 00 0c 02 6e 10 ?? ?? 02 00 0c 02 71 30 ?? ?? 21 0a 38 09 de ff 72 10 ?? 02 09 00 28 d9 0d 01 38 09 05 00 72 10 ?? 02 09 00 27 01 }
		$S_4_1a448 = { 1a 02 ?? ?? 08 00 16 00 6e 20 ?? ?? 20 00 0c 14 12 62 46 10 14 02 08 00 15 00 54 02 ?? ?? 1a 03 ?? ?? 12 54 23 44 ?? ?? 12 05 1a 06 ?? ?? 4d 06 04 05 12 15 1a 06 ?? ?? 4d 06 04 05 12 25 1a 06 ?? ?? 4d 06 04 05 12 35 1a 06 ?? ?? 4d 06 04 05 12 45 1a 06 ?? ?? 4d 06 04 05 1a 05 ?? ?? 12 16 23 66 ?? ?? 12 07 4d 10 06 07 12 07 12 08 12 09 74 08 ?? ?? 02 00 0c 11 39 11 14 00 22 02 ?? ?? 1a 03 ?? ?? 70 20 ?? ?? 32 00 27 02 0d 0b 62 02 ?? ?? 1a 03 ?? ?? 71 30 ?? ?? 32 0b 12 0f 11 0f 78 01 ?? 02 11 00 0a 12 3c 12 23 00 22 02 ?? ?? 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 02 00 12 00 6e 20 ?? ?? 03 00 0c 03 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 03 70 20 ?? ?? 32 00 27 02 12 0e 78 01 ?? 02 11 00 0a 02 38 02 1b 00 1a 02 ?? ?? 08 00 11 00 72 20 ?? 02 20 00 0a 02 08 00 11 00 72 20 ?? 02 20 00 0c 13 1a 02 ?? ?? 08 00 13 00 6e 20 ?? ?? 02 00 0a 02 38 02 e4 ff 12 1e 39 0e 05 00 78 01 ?? 02 11 00 1a 02 ?? ?? 08 00 11 00 72 20 ?? 02 20 00 0a 02 08 00 11 00 72 20 ?? 02 20 00 0c 0a 1a 02 ?? ?? 08 00 11 00 72 20 ?? 02 20 00 0a 02 08 00 11 00 72 20 ?? 02 20 00 0c 0d 1a 02 ?? ?? 08 00 11 00 72 20 ?? 02 20 00 0a 02 08 00 11 00 72 20 ?? 02 20 00 0b 02 71 20 ?? ?? 32 00 0c 0c 22 0f ?? ?? 70 10 ?? ?? 0f 00 6e 20 ?? ?? af 00 6e 20 ?? ?? df 00 12 12 46 02 14 02 6e 20 ?? ?? 2f 00 6e 20 ?? ?? cf 00 29 00 71 ff }
		$S_4_71416 = { 71 10 ?? ?? 0c 00 0a 05 38 05 1c 00 1a 05 ?? ?? 6e 20 ?? ?? 5d 00 0a 05 39 05 12 00 1a 05 ?? ?? 6e 20 ?? ?? 5d 00 0a 05 39 05 0a 00 1a 05 ?? ?? 6e 20 ?? ?? 5d 00 0a 05 38 05 36 00 1a 0c ?? ?? 12 03 1a 05 ?? ?? 6e 20 ?? ?? 5c 00 0a 05 38 05 33 00 12 15 70 30 ?? ?? ca 05 0c 05 71 20 ?? ?? d5 00 0c 03 6e 10 ?? ?? 0b 00 0c 05 6e 20 ?? ?? 5b 00 62 05 ?? ?? 6e 20 ?? ?? 5b 00 39 03 87 00 22 05 ?? ?? 1a 06 ?? ?? 70 20 ?? ?? 65 00 27 05 0d 01 62 05 ?? ?? 1a 06 ?? ?? 71 30 ?? ?? 65 01 12 05 0f 05 22 05 ?? ?? 1a 06 ?? ?? 70 20 ?? ?? 65 00 27 05 1a 05 ?? ?? 6e 20 ?? ?? 5c 00 0a 05 38 05 49 00 62 05 ?? ?? 6e 20 ?? ?? 5b 00 22 00 ?? ?? 1a 05 ?? 05 70 20 ?? ?? 50 00 22 04 ?? ?? 1a 05 ?? 05 70 20 ?? ?? 54 00 12 02 6e 10 ?? ?? 0b 00 0a 05 38 05 0c 00 71 20 ?? ?? d4 00 0c 02 39 02 06 00 71 20 ?? ?? d0 00 0c 02 39 02 1c 00 6e 10 ?? ?? 0f 00 0b 06 6e 10 ?? ?? 0e 00 0b 08 71 59 ?? ?? 64 87 0c 02 39 02 0e 00 6e 10 ?? ?? 0f 00 0b 06 6e 10 ?? ?? 0e 00 0b 08 71 59 ?? ?? 60 87 0c 02 38 02 9c ff 6e 10 ?? ?? 02 00 0c 03 28 96 54 a5 ?? ?? 62 06 ?? ?? 22 07 ?? ?? 70 10 ?? ?? 07 00 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 20 ?? ?? c7 00 0c 07 6e 10 ?? ?? 07 00 0c 07 71 30 ?? ?? 65 07 29 00 7b ff 54 a5 ?? ?? 74 01 ?? ?? 10 00 0a 06 6e 56 ?? ?? 5a 3b 12 15 28 82 }
		$S_4_12144 = { 12 12 12 03 1d 08 54 84 ?? ?? 71 00 ?? ?? 00 00 0c 05 6e 10 ?? ?? 08 00 0c 06 12 17 71 40 ?? ?? 54 76 0a 01 39 01 1d 00 54 82 ?? ?? 12 04 71 20 ?? ?? 42 00 22 02 ?? ?? 1a 04 ?? ?? 70 20 ?? ?? 42 00 27 02 0d 00 54 82 ?? ?? 71 10 ?? ?? 02 00 0c 02 6e 20 ?? ?? 02 00 01 32 1e 08 0f 02 6e 10 ?? ?? 08 00 0c 04 6e 20 ?? ?? 48 00 0c 04 5b 84 ?? ?? 54 84 ?? ?? 39 04 f2 ff 22 02 ?? ?? 1a 04 ?? ?? 70 20 ?? ?? 42 00 27 02 0d 02 1e 08 27 02 }
		$S_4_22222 = { 22 04 ?? ?? 6e 10 ?? ?? 0d 00 0c 07 70 20 ?? ?? 74 00 6e 10 ?? ?? 04 00 0a 05 12 03 35 53 5f 00 6e 20 ?? ?? 34 00 0c 07 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 06 71 10 ?? 05 06 00 0c 02 6e 10 ?? 05 02 00 0c 01 62 07 ?? ?? 22 08 ?? ?? 70 10 ?? ?? 08 00 1a 09 ?? ?? 6e 20 ?? ?? 98 00 0c 08 6e 20 ?? ?? 68 00 0c 08 1a 09 ?? ?? 6e 20 ?? ?? 98 00 0c 08 6e 20 ?? ?? 18 00 0c 08 6e 10 ?? ?? 08 00 0c 08 71 20 ?? ?? 87 00 6e 5e ?? ?? ba 1d 12 17 0f 07 0d 00 62 07 ?? ?? 22 08 ?? ?? 70 10 ?? ?? 08 00 1a 09 ?? ?? 6e 20 ?? ?? 98 00 0c 08 6e 20 ?? ?? 38 00 0c 08 6e 10 ?? ?? 08 00 0c 08 71 20 ?? ?? 87 00 d8 03 03 01 28 aa 0d 00 62 07 ?? ?? 1a 08 ?? ?? 71 30 ?? ?? 87 00 12 07 28 da }
		$S_4_39192 = { 39 07 13 00 22 02 ?? ?? 1a 03 ?? ?? 70 20 ?? ?? 32 00 27 02 0d 00 62 02 ?? ?? 1a 03 ?? ?? 71 30 ?? ?? 32 00 0e 00 71 00 ?? ?? 00 00 0a 02 72 20 ?? 02 26 00 0a 02 71 10 ?? ?? 02 00 0c 01 39 01 1f 00 22 02 ?? ?? 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 07 00 0c 04 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 03 70 20 ?? ?? 32 00 27 02 6e 10 ?? ?? 01 00 0a 02 2c 02 14 00 00 00 62 02 ?? ?? 6e 20 ?? ?? 27 00 28 c8 62 02 ?? ?? 6e 20 ?? ?? 27 00 62 02 ?? ?? 6e 20 ?? ?? 27 00 28 bd 00 02 02 00 44 00 00 00 c9 00 00 00 09 00 00 00 0e 00 00 00 }
		$S_4_71372 = { 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 02 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 03 6e 20 ?? ?? 28 00 0c 01 1f 01 ?? ?? 22 05 ?? ?? 70 10 ?? ?? 05 00 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 06 6e 20 ?? ?? 65 00 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 00 6e 20 ?? ?? 05 00 38 00 0b 00 54 86 ?? ?? 71 20 ?? ?? 06 00 0c 06 6e 20 ?? ?? 65 00 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 06 6e 20 ?? ?? 65 00 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0a 06 38 06 5d 00 12 16 6e 20 ?? ?? 65 00 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0b 06 6e 30 ?? ?? 65 07 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 06 6e 20 ?? ?? 65 00 6e 10 ?? ?? 05 00 0c 06 1a 07 ?? ?? 6e 20 ?? ?? 76 00 0a 06 38 06 39 00 70 30 ?? ?? 58 09 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 06 6e 20 ?? ?? 65 00 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 06 6e 20 ?? ?? 65 00 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 06 6e 20 ?? ?? 65 00 70 40 ?? ?? 18 03 54 86 ?? ?? 6e 10 ?? ?? 0a 00 0a 07 70 57 ?? ?? 68 51 0a 04 6e 20 ?? ?? 51 00 11 05 12 06 28 a5 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 69 00 0c 06 6e 20 ?? ?? 65 00 28 c1 }
		$S_4_54142 = { 54 52 ?? ?? 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 72 10 ?? 02 06 00 0a 04 6e 20 ?? ?? 43 00 0c 03 1a 04 ?? 01 6e 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? 73 00 0c 03 6e 10 ?? ?? 03 00 0c 03 71 20 ?? ?? 32 00 22 01 ?? ?? 70 10 ?? ?? 01 00 38 06 1b 00 72 10 ?? 02 06 00 0a 02 38 02 15 00 6e 30 ?? ?? 65 08 0c 00 38 00 05 00 72 20 ?? ?? 01 00 d8 07 07 ff 72 10 ?? 02 06 00 0a 02 38 02 04 00 3c 07 ef ff 11 01 }
		$S_4_2270 = { 22 02 ?? ?? 70 20 ?? ?? 52 00 6e 10 ?? ?? 02 00 0c 01 12 02 13 03 2e 00 6e 20 ?? ?? 31 00 0a 03 6e 30 ?? ?? 21 03 0c 01 70 20 ?? ?? 14 00 0c 02 11 02 0d 00 62 02 ?? ?? 1a 03 ?? ?? 71 30 ?? ?? 32 00 12 02 28 f6 }
		$S_4_12246 = { 12 1d 12 0e 1d 0f 6f 10 ?? ?? 0f 00 0a 00 38 00 6f 00 54 f0 ?? ?? 71 20 ?? ?? f0 00 1a 00 ?? ?? 6e 20 ?? ?? 0f 00 0c 00 5b f0 ?? ?? 22 00 ?? ?? 70 10 ?? ?? 00 00 5b f0 ?? ?? 54 f0 ?? ?? 1a 01 ?? 0a 12 22 23 22 ?? ?? 12 03 1a 04 ?? ?? 4d 04 02 03 12 13 1a 04 ?? ?? 4d 04 02 03 12 03 12 04 12 05 12 06 12 07 74 08 ?? ?? 00 00 0c 09 38 09 34 00 72 10 ?? 02 09 00 0a 00 38 00 2e 00 1a 00 ?? ?? 72 20 ?? 02 09 00 0a 0b 1a 00 ?? ?? 72 20 ?? 02 09 00 0a 0c 22 08 ?? ?? 72 20 ?? 02 c9 00 0c 00 72 20 ?? 02 b9 00 0c 01 70 30 ?? ?? 08 01 54 f0 ?? ?? 72 20 ?? ?? 80 00 72 10 ?? 02 09 00 0a 00 38 00 0a 00 72 10 ?? 02 09 00 0a 00 13 01 0a 00 34 10 e2 ff 01 d0 1e 0f 0f 00 0d 0a 54 f0 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 0a 01 e0 28 f5 0d 00 1e 0f 27 00 }
		$S_4_2272 = { 22 00 ?? ?? 70 20 ?? ?? 80 00 6e 10 ?? ?? 00 00 0a 02 38 02 0c 00 6e 10 ?? ?? 00 00 0b 02 16 04 00 00 31 02 02 04 3c 02 07 00 12 02 71 30 ?? ?? 97 02 0c 08 11 08 0d 01 54 62 ?? ?? 1a 03 ?? ?? 71 30 ?? ?? 32 01 28 f7 }
		$S_4_7144 = { 71 10 ?? ?? 03 00 0a 01 39 01 10 00 13 01 40 00 6e 20 ?? ?? 13 00 0a 00 3d 00 08 00 12 01 6e 30 ?? ?? 13 00 0c 01 11 01 12 01 28 fe }
		$S_4_7146 = { 71 10 ?? ?? 02 00 0a 00 39 00 11 00 54 10 ?? ?? 71 10 ?? ?? 00 00 0a 00 39 00 09 00 54 10 ?? ?? 6e 20 ?? ?? 20 00 0a 00 0f 00 12 00 28 fe }
		$S_4_39158 = { 39 08 13 00 22 04 ?? ?? 1a 05 ?? ?? 70 20 ?? ?? 54 00 27 04 0d 00 54 74 ?? ?? 1a 05 ?? ?? 71 30 ?? ?? 54 00 0e 00 22 03 ?? ?? 12 24 62 05 ?? ?? 22 06 ?? ?? 70 30 ?? ?? 76 08 70 40 ?? ?? 43 65 22 02 ?? ?? 70 10 ?? ?? 02 00 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 04 ?? ?? 6e 10 ?? ?? 08 00 0c 05 6e 30 ?? ?? 41 05 1a 04 ?? ?? 12 05 71 10 ?? ?? 05 00 0c 05 6e 30 ?? ?? 41 05 6e 20 ?? ?? 12 00 1a 04 ?? ?? 6e 10 ?? ?? 02 00 0c 05 6e 30 ?? ?? 43 05 54 74 ?? ?? 71 20 ?? ?? 34 00 28 c4 }
		$S_4_5542 = { 55 31 ?? ?? 38 01 02 00 62 01 ?? ?? 1a 02 ?? ?? 71 20 ?? ?? 21 00 0e 00 0d 00 62 01 ?? ?? 1a 02 ?? ?? 71 30 ?? ?? 21 00 28 f7 }
		$S_4_1244 = { 12 01 38 05 0b 00 54 42 ?? ?? 6e 20 ?? ?? 52 00 0a 02 38 02 03 00 12 11 0f 01 0d 00 54 42 ?? ?? 1a 03 ?? ?? 71 30 ?? ?? 32 00 28 f7 }
		$S_4_1a164 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_12120 = { 12 0a 1a 01 ?? ?? 12 10 23 02 ?? ?? 12 00 1a 03 ?? ?? 4d 03 02 00 1a 03 ?? ?? 12 04 12 05 12 06 12 07 07 c0 74 08 ?? ?? 00 00 0c 09 72 10 ?? 02 09 00 0a 00 38 00 20 00 22 00 ?? ?? 1a 01 ?? ?? 72 20 ?? 02 19 00 0a 01 72 20 ?? 02 19 00 0c 01 70 20 ?? ?? 10 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 11 00 0d 08 62 00 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 08 07 a0 28 f6 }
		$S_4_12328 = { 12 06 12 07 54 90 ?? ?? 1a 01 ?? ?? 71 20 ?? ?? 10 00 54 90 ?? ?? 6e 10 ?? 01 00 00 0c 00 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 0c 01 6e 20 ?? ?? a1 00 0c 01 1a 02 ?? ?? 6e 20 ?? ?? 21 00 0c 01 6e 10 ?? ?? 01 00 0c 01 71 10 ?? 05 01 00 0c 01 12 02 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? a3 00 0c 03 1a 04 ?? 00 6e 20 ?? ?? 43 00 0c 04 38 0b 4a 00 13 03 97 00 6e 20 ?? ?? 34 00 0c 03 6e 10 ?? ?? 03 00 0c 03 12 04 12 05 74 06 ?? 01 00 00 0c 07 54 90 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 0c 01 72 10 ?? 02 07 00 0a 02 6e 20 ?? ?? 21 00 0c 01 1a 02 ?? 00 6e 20 ?? ?? 21 00 0c 01 6e 10 ?? ?? 01 00 0c 01 71 20 ?? ?? 10 00 72 10 ?? 02 07 00 0a 00 38 00 0c 00 1a 00 ?? ?? 72 20 ?? 02 07 00 0a 00 72 20 ?? 02 07 00 0c 06 38 07 05 00 72 10 ?? 02 07 00 11 06 13 03 89 00 28 b8 0d 08 54 90 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 08 38 07 f4 ff 72 10 ?? 02 07 00 28 ef 0d 00 38 07 05 00 72 10 ?? 02 07 00 27 00 }
		$S_4_71790 = { 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0c 0e 08 00 18 00 6e 20 ?? ?? e0 00 0c 09 22 03 ?? ?? 70 10 ?? ?? 03 00 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0c 0d 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0c 0b 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0c 10 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0c 04 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0c 05 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0c 12 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0b 14 77 02 ?? ?? 14 00 0c 07 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0b 14 77 02 ?? ?? 14 00 0c 06 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0b 14 77 02 ?? ?? 14 00 0c 11 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0b 14 77 02 ?? ?? 14 00 0c 0f 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0c 02 6e 20 ?? ?? 23 00 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0a 02 38 02 ab 00 12 12 6e 20 ?? ?? 23 00 6e 20 ?? ?? b3 00 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0b 14 05 00 14 00 6e 30 ?? ?? 03 01 71 00 ?? ?? 00 00 0a 02 08 00 19 00 72 20 ?? 02 20 00 0c 02 6e 20 ?? ?? 23 00 74 01 ?? ?? 11 00 0b 14 16 16 08 00 31 02 14 16 39 02 81 00 12 12 6e 20 ?? ?? 23 00 6e 20 ?? ?? f3 00 6e 10 ?? ?? 03 00 0a 02 39 02 09 00 6e 10 ?? ?? 09 00 0c 02 6e 20 ?? ?? 23 00 12 0a 6e 10 ?? ?? 09 00 0a 02 38 02 7a 00 38 12 66 00 74 01 ?? ?? 12 00 0a 02 39 02 60 00 08 00 18 00 08 01 12 00 70 20 ?? ?? 10 00 0c 13 08 00 18 00 54 02 ?? ?? 08 00 12 00 08 01 13 00 6e 30 ?? ?? 02 01 0c 0a 08 00 13 00 6e 20 ?? ?? 03 00 71 10 ?? ?? 0a 00 0c 0a 08 00 18 00 54 02 ?? ?? 71 30 ?? ?? a2 0a 0c 02 6e 20 ?? ?? 23 00 6e 20 ?? ?? e3 00 6e 10 ?? ?? 03 00 0a 02 39 02 24 00 74 01 ?? ?? 1a 00 0a 02 08 00 18 00 08 01 19 00 70 52 ?? ?? 30 14 71 10 ?? ?? 05 00 0a 02 38 02 0c 00 38 04 44 00 1a 02 ?? ?? 6e 20 ?? ?? 24 00 0a 02 38 02 3c 00 08 02 18 00 08 08 1a 00 76 07 ?? ?? 02 00 38 09 05 00 6e 20 ?? ?? 39 00 11 03 12 02 29 00 57 ff 12 02 28 81 1a 0a ?? ?? 1a 02 ?? 05 6e 20 ?? ?? 23 00 28 b4 0d 0c 62 02 ?? ?? 1a 08 ?? ?? 71 30 ?? ?? 82 0c 12 03 28 e9 08 00 18 00 70 20 ?? ?? e0 00 0c 13 08 00 18 00 54 02 ?? ?? 08 00 13 00 6e 30 ?? ?? e2 00 0c 0a 08 00 13 00 6e 20 ?? ?? 03 00 28 94 77 01 ?? ?? 10 00 0a 02 39 02 c9 ff 08 00 10 00 6e 20 ?? ?? 03 00 6e 10 ?? ?? 03 00 0c 02 6e 20 ?? ?? 23 00 28 bb }
		$S_4_54318 = { 54 e9 ?? ?? 1a 0a ?? ?? 71 20 ?? ?? a9 00 12 03 12 04 12 00 22 07 ?? ?? 70 10 ?? ?? 07 00 22 09 ?? ?? 70 10 ?? ?? 09 00 1a 0a ?? ?? 6e 20 ?? ?? a9 00 0c 09 6e 20 ?? ?? f9 00 0c 09 6e 10 ?? ?? 09 00 0c 09 71 10 ?? 05 09 00 0c 06 54 e9 ?? ?? 6e 10 ?? 01 09 00 0c 09 6e 20 ?? 01 69 00 0c 03 38 03 1e 00 22 05 ?? ?? 1a 09 ?? ?? 70 30 ?? ?? 35 09 22 01 ?? ?? 70 20 ?? ?? 51 00 6e 10 ?? ?? 01 00 0c 08 38 08 0a 00 6e 20 ?? ?? 87 00 6e 10 ?? ?? 01 00 0c 08 28 f7 07 10 07 54 6e 10 ?? ?? 03 00 6e 10 ?? ?? 04 00 6e 10 ?? ?? 00 00 6e 10 ?? ?? 07 00 0c 09 11 09 0d 02 54 e9 ?? ?? 54 ea ?? ?? 1a 0b ?? ?? 1a 0c ?? ?? 62 0d ?? ?? 71 5d ?? ?? a9 cb 6e 10 ?? ?? 03 00 6e 10 ?? ?? 04 00 6e 10 ?? ?? 00 00 28 e4 0d 09 28 e2 0d 09 6e 10 ?? ?? 03 00 6e 10 ?? ?? 04 00 6e 10 ?? ?? 00 00 27 09 0d 09 28 cf 0d 09 28 d0 0d 09 28 d1 0d 09 28 e5 0d 09 28 e6 0d 0a 28 ee 0d 0a 28 ef 0d 0a 28 f0 0d 09 07 54 28 e4 0d 09 07 10 07 54 28 e0 0d 02 07 54 28 c3 0d 02 07 10 07 54 28 bf }
		$S_4_2290 = { 22 02 ?? ?? 22 05 ?? ?? 70 20 ?? ?? 85 00 70 20 ?? ?? 52 00 22 04 ?? ?? 70 10 ?? ?? 04 00 13 05 00 04 23 50 ?? ?? 6e 20 ?? ?? 02 00 0a 03 3d 03 11 00 12 05 6e 40 ?? ?? 04 35 28 f6 0d 01 62 05 ?? ?? 1a 06 ?? ?? 71 30 ?? ?? 65 01 12 05 11 05 6e 10 ?? ?? 04 00 0c 05 28 fb }
		$S_4_1a294 = { 1a 07 ?? ?? 6e 20 ?? ?? 7c 00 0c 03 12 37 46 00 03 07 12 47 46 02 03 07 6e 10 ?? ?? 0a 00 0c 07 71 10 ?? ?? 07 00 0c 06 22 07 ?? ?? 70 10 ?? ?? 07 00 6e 20 ?? ?? 67 00 0c 07 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 20 ?? ?? 07 00 0c 07 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 10 ?? ?? 07 00 0c 06 22 07 ?? ?? 70 10 ?? ?? 07 00 6e 20 ?? ?? 67 00 0c 07 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 20 ?? ?? 27 00 0c 07 6e 10 ?? ?? 07 00 0c 06 71 10 ?? ?? 0e 00 0a 07 38 07 25 00 22 07 ?? ?? 1a 08 ?? ?? 70 20 ?? ?? 87 00 27 07 0d 01 12 17 71 20 ?? ?? 76 00 0b 04 12 17 71 20 ?? ?? 76 00 0a 07 38 07 0e 00 53 a8 ?? ?? 71 40 ?? ?? 54 98 0a 07 38 07 06 00 12 17 71 30 ?? ?? d6 07 12 07 0f 07 1a 07 ?? 05 6e 20 ?? ?? 7e 00 0a 07 38 07 0a 00 22 07 ?? ?? 1a 08 ?? ?? 70 20 ?? ?? 87 00 27 07 71 10 ?? ?? 0e 00 0c 07 6e 10 ?? ?? 07 00 0b 04 28 d3 0d 01 54 a7 ?? ?? 1a 08 ?? ?? 71 30 ?? ?? 87 01 28 dd }
		$S_4_1228 = { 12 00 70 20 ?? ?? 42 00 0c 00 71 10 ?? ?? 00 00 0a 01 39 01 03 00 11 00 12 00 28 fe }
		$S_4_7016 = { 70 10 ?? ?? 01 00 0c 00 5b 10 ?? ?? 12 10 0f 00 }
		$S_4_1a56 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_1a50 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 0e 00 }
		$S_4_1a52 = { 1a 02 ?? ?? 71 10 ?? ?? 02 00 0c 00 1a 02 ?? ?? 12 13 71 30 ?? ?? 20 03 0c 02 11 02 0d 01 62 02 ?? ?? 1a 03 ?? ?? 71 30 ?? ?? 32 01 12 02 23 22 ?? ?? 28 f4 }
		$S_4_12446 = { 12 07 12 18 1d 0c 70 10 ?? ?? 0c 00 0c 09 5b c9 ?? ?? 62 09 ?? ?? 22 0a ?? ?? 70 10 ?? ?? 0a 00 1a 0b ?? ?? 6e 20 ?? ?? ba 00 0c 0a 54 cb ?? ?? 71 10 ?? ?? 0b 00 0c 0b 6e 20 ?? ?? ba 00 0c 0a 6e 10 ?? ?? 0a 00 0c 0a 71 20 ?? ?? a9 00 70 10 ?? ?? 0c 00 0c 00 22 09 ?? ?? 70 10 ?? ?? 09 00 6e 20 ?? ?? 09 00 0c 09 6e 10 ?? ?? 0c 00 0c 0a 6e 20 ?? ?? a9 00 0c 09 6e 10 ?? ?? 09 00 0c 06 22 09 ?? ?? 70 10 ?? ?? 09 00 71 00 ?? ?? 00 00 0c 0a 6e 20 ?? ?? a9 00 0c 09 1a 0a ?? ?? 6e 20 ?? ?? a9 00 0c 09 1a 0a ?? ?? 6e 20 ?? ?? a9 00 0c 09 6e 10 ?? ?? 09 00 0c 05 12 19 71 30 ?? ?? 56 09 0a 09 39 09 04 00 1e 0c 0f 07 22 09 ?? ?? 70 10 ?? ?? 09 00 6e 20 ?? ?? 09 00 0c 09 1a 0a ?? ?? 6e 20 ?? ?? a9 00 0c 09 1a 0a ?? ?? 6e 20 ?? ?? a9 00 0c 09 6e 10 ?? ?? 09 00 0c 03 22 09 ?? ?? 70 10 ?? ?? 09 00 12 1a 71 10 ?? ?? 0a 00 0c 0a 6e 20 ?? ?? a9 00 0c 09 1a 0a ?? ?? 6e 20 ?? ?? a9 00 0c 09 1a 0a ?? ?? 6e 20 ?? ?? a9 00 0c 09 6e 10 ?? ?? 09 00 0c 02 12 19 71 30 ?? ?? 23 09 0a 09 38 09 c2 ff 1a 09 ?? ?? 6e 20 ?? ?? 9c 00 0c 09 5b c9 ?? ?? 1a 09 ?? ?? 6e 20 ?? ?? 9c 00 0c 01 54 c9 ?? ?? 39 09 16 00 22 08 ?? ?? 1a 09 ?? ?? 70 20 ?? ?? 98 00 27 08 0d 04 62 08 ?? ?? 1a 09 ?? ?? 71 30 ?? ?? 98 04 28 9e 0d 07 1e 0c 27 07 39 01 0a 00 22 08 ?? ?? 1a 09 ?? ?? 70 20 ?? ?? 98 00 27 08 22 09 ?? ?? 54 ca ?? ?? 70 30 ?? ?? a9 01 5b c9 ?? ?? 01 87 28 86 }
		$S_4_7158 = { 71 00 ?? ?? 00 00 0a 00 38 00 05 00 62 00 ?? 00 11 00 71 00 ?? ?? 00 00 0a 00 38 00 09 00 1a 00 ?? ?? 71 10 ?? 05 00 00 0c 00 28 f3 1a 00 ?? ?? 71 10 ?? 05 00 00 0c 00 28 ec }
		$S_4_1d98 = { 1d 04 70 10 ?? ?? 04 00 0c 01 5b 41 ?? ?? 6f 10 ?? ?? 04 00 0a 01 38 01 21 00 54 41 ?? ?? 38 01 1d 00 22 01 ?? ?? 54 42 ?? ?? 54 43 ?? ?? 70 30 ?? ?? 21 03 5b 41 ?? ?? 54 41 ?? ?? 6e 10 ?? ?? 01 00 12 11 1e 04 0f 01 0d 00 62 01 ?? ?? 1a 02 ?? ?? 71 30 ?? ?? 21 00 12 01 28 f5 0d 01 1e 04 27 01 }
		$S_4_6e124 = { 6e 10 ?? ?? 04 00 0a 01 39 01 18 00 6e 20 ?? ?? 54 00 6e 10 ?? ?? 04 00 0a 01 38 01 24 00 6e 10 ?? ?? 04 00 0c 01 6e 30 ?? ?? 13 05 0c 00 38 00 06 00 6e 20 ?? ?? 04 00 0e 00 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 0c 01 6e 20 ?? ?? 51 00 0c 01 6e 10 ?? ?? 01 00 0c 00 28 e9 6e 20 ?? ?? 64 00 54 31 ?? ?? 71 20 ?? ?? 61 00 0c 01 6e 20 ?? ?? 14 00 28 df }
		$S_4_38258 = { 38 0d 61 00 1a 00 ?? ?? 6e 20 ?? ?? 0d 00 0a 00 38 00 59 00 71 00 ?? ?? 00 00 0a 00 72 20 ?? 02 0e 00 0c 0a 38 0a 4f 00 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 6e 10 ?? ?? 0c 00 0c 01 6e 20 ?? ?? 10 00 0c 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 71 00 ?? ?? 00 00 0b 04 6e 30 ?? ?? 40 05 0c 00 1a 01 ?? ?? 6e 20 ?? ?? 10 00 0c 00 6e 10 ?? ?? 00 00 0c 08 71 10 ?? ?? 08 00 0c 03 22 06 ?? ?? 70 20 ?? ?? 36 00 71 20 ?? ?? 6a 00 0a 00 39 00 16 00 22 00 ?? ?? 1a 01 ?? ?? 70 20 ?? ?? 10 00 27 00 0d 07 54 b0 ?? ?? 62 01 ?? ?? 1a 02 ?? ?? 12 04 71 57 ?? ?? 10 42 0e 00 07 69 54 b1 ?? ?? 12 15 07 b0 07 c2 01 f4 74 06 ?? ?? 00 00 0c 06 6e 10 ?? ?? 09 00 6e 10 ?? ?? 06 00 0c 00 6e 20 ?? ?? 0c 00 54 b0 ?? ?? 62 01 ?? ?? 1a 02 ?? ?? 71 30 ?? ?? 10 02 28 e1 }
		$S_4_6042 = { 60 03 ?? ?? 72 20 ?? 02 35 00 0c 01 60 03 ?? ?? 72 20 ?? 02 35 00 0c 02 22 00 ?? ?? 70 30 ?? ?? 10 02 70 20 ?? ?? 04 00 11 00 }
		$S_4_71228 = { 71 00 ?? ?? 00 00 0a 06 72 20 ?? 02 6a 00 0c 01 1a 06 ?? ?? 6e 20 ?? ?? 61 00 0a 06 38 06 35 00 1a 06 ?? ?? 6e 20 ?? ?? 61 00 0c 05 54 86 ?? ?? 12 17 46 07 05 07 71 20 ?? ?? 76 00 0c 00 39 00 05 00 12 16 46 00 05 06 12 26 46 04 05 06 12 36 46 03 05 06 39 04 1d 00 22 06 ?? ?? 70 10 ?? ?? 06 00 6e 20 ?? ?? 06 00 0c 06 1a 07 ?? 00 6e 20 ?? ?? 76 00 0c 06 6e 20 ?? ?? 36 00 0c 06 6e 10 ?? ?? 06 00 0c 01 6e 20 ?? ?? 19 00 0e 00 22 06 ?? ?? 70 10 ?? ?? 06 00 6e 20 ?? ?? 06 00 0c 06 1a 07 ?? 00 6e 20 ?? ?? 76 00 0c 06 6e 20 ?? ?? 46 00 0c 06 1a 07 ?? 02 6e 20 ?? ?? 76 00 0c 06 6e 20 ?? ?? 36 00 0c 06 6e 10 ?? ?? 06 00 0c 01 28 db 0d 02 54 86 ?? ?? 1a 07 ?? ?? 71 30 ?? ?? 76 02 28 d5 }
		$S_4_12132 = { 12 03 22 09 ?? ?? 70 10 ?? ?? 09 00 54 a0 ?? ?? 62 01 ?? 00 12 22 23 22 ?? ?? 12 04 1a 05 ?? ?? 4d 05 02 04 12 14 1a 05 ?? ?? 4d 05 02 04 1a 05 ?? ?? 07 34 74 06 ?? 01 00 00 0c 08 38 08 23 00 1a 00 ?? ?? 72 20 ?? 02 08 00 0a 06 1a 00 ?? ?? 72 20 ?? 02 08 00 0a 07 72 10 ?? 02 08 00 0a 00 38 00 0e 00 72 20 ?? 02 68 00 0a 00 72 20 ?? 02 78 00 0c 01 6e 30 ?? ?? 09 01 28 ef 72 10 ?? 02 08 00 11 09 }
		$S_4_1a110 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_08238 = { 08 00 14 00 52 04 ?? ?? 08 00 15 00 72 20 ?? 02 40 00 0c 05 08 00 14 00 52 04 ?? ?? 08 00 15 00 72 20 ?? 02 40 00 0b 08 71 20 ?? ?? 98 00 0c 12 08 00 14 00 52 04 ?? ?? 08 00 15 00 72 20 ?? 02 40 00 0a 04 71 10 ?? ?? 04 00 0c 13 08 00 14 00 08 01 13 00 6e 20 ?? ?? 10 00 0a 0a 08 00 14 00 70 30 ?? ?? 50 0a 0c 07 39 07 1d 00 22 04 ?? ?? 1a 08 ?? ?? 70 20 ?? ?? 84 00 27 04 0d 10 08 00 14 00 54 0c ?? ?? 08 00 14 00 54 0d ?? ?? 1a 0e ?? ?? 12 0f 62 11 ?? ?? 77 06 ?? ?? 0c 00 12 03 11 03 08 00 14 00 54 04 ?? ?? 6e 20 ?? ?? 54 00 0c 02 6e 10 ?? ?? 02 00 0c 04 71 10 ?? ?? 04 00 0c 06 6e 10 ?? ?? 02 00 0c 0b 22 03 ?? ?? 08 00 14 00 54 04 ?? ?? 74 01 ?? ?? 12 00 0b 08 71 20 ?? ?? 98 00 0b 08 76 09 ?? ?? 03 00 28 da }
		$S_4_1a182 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_22286 = { 22 03 ?? ?? 70 10 ?? ?? 03 00 71 00 ?? ?? 00 00 0a 04 72 20 ?? 02 47 00 0c 04 6e 20 ?? ?? 43 00 71 00 ?? ?? 00 00 0a 04 72 20 ?? 02 47 00 0b 04 6e 30 ?? ?? 43 05 71 00 ?? ?? 00 00 0a 04 72 20 ?? 02 47 00 0c 04 6e 20 ?? ?? 43 00 71 00 ?? ?? 00 00 0a 04 72 20 ?? 02 47 00 0c 02 6e 20 ?? ?? 23 00 71 00 ?? ?? 00 00 0a 04 72 20 ?? 02 47 00 0c 04 6e 20 ?? ?? 43 00 71 00 ?? ?? 00 00 0a 04 72 20 ?? 02 47 00 0c 04 6e 20 ?? ?? 43 00 71 00 ?? ?? 00 00 0a 04 72 20 ?? 02 47 00 0c 04 6e 20 ?? ?? 43 00 38 02 0a 00 54 64 ?? ?? 6e 20 ?? ?? 42 00 0a 04 38 04 1b 00 12 14 6e 20 ?? ?? 43 00 71 00 ?? ?? 00 00 0a 04 72 20 ?? 02 47 00 0c 00 38 00 1b 00 70 20 ?? ?? 06 00 0c 04 6e 20 ?? ?? 43 00 70 30 ?? ?? 76 03 11 03 12 04 6e 20 ?? ?? 43 00 28 e7 0d 01 62 04 ?? ?? 1a 05 ?? ?? 71 30 ?? ?? 54 01 28 f2 71 00 ?? ?? 00 00 0a 04 72 20 ?? 02 47 00 0c 04 6e 20 ?? ?? 43 00 28 e3 }
		$S_4_13210 = { 13 00 12 00 23 00 ?? ?? 12 01 1a 02 ?? ?? 4d 02 00 01 12 11 1a 02 ?? ?? 4d 02 00 01 12 21 1a 02 ?? ?? 4d 02 00 01 12 31 1a 02 ?? ?? 4d 02 00 01 12 41 1a 02 ?? ?? 4d 02 00 01 12 51 1a 02 ?? ?? 4d 02 00 01 12 61 1a 02 ?? ?? 4d 02 00 01 12 71 1a 02 ?? ?? 4d 02 00 01 13 01 08 00 1a 02 ?? ?? 4d 02 00 01 13 01 09 00 1a 02 ?? ?? 4d 02 00 01 13 01 0a 00 1a 02 ?? ?? 4d 02 00 01 13 01 0b 00 1a 02 ?? ?? 4d 02 00 01 13 01 0c 00 1a 02 ?? ?? 4d 02 00 01 13 01 0d 00 1a 02 ?? ?? 4d 02 00 01 13 01 0e 00 1a 02 ?? ?? 4d 02 00 01 13 01 0f 00 1a 02 ?? ?? 4d 02 00 01 13 01 10 00 1a 02 ?? ?? 4d 02 00 01 13 01 11 00 1a 02 ?? ?? 4d 02 00 01 11 00 }
		$S_4_6298 = { 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 62 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 0e 00 }
		$S_8_1a82 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 59 10 ?? ?? 0e 00 }
		$S_8_1a218 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_39150 = { 39 08 14 00 22 05 ?? ?? 1a 06 ?? ?? 70 20 ?? ?? 65 00 27 05 0d 01 54 75 ?? ?? 1a 06 ?? ?? 71 30 ?? ?? 65 01 12 05 11 05 6e 10 ?? ?? 08 00 0c 00 39 00 0a 00 22 05 ?? ?? 1a 06 ?? ?? 70 20 ?? ?? 65 00 27 05 1a 05 ?? ?? 6e 20 ?? ?? 50 00 0a 02 3c 02 0a 00 22 05 ?? ?? 1a 06 ?? ?? 70 20 ?? ?? 65 00 27 05 13 05 22 00 6e 30 ?? ?? 50 02 0a 04 3c 04 0a 00 22 05 ?? ?? 1a 06 ?? ?? 70 20 ?? ?? 65 00 27 05 6e 30 ?? ?? 20 04 0c 03 70 20 ?? ?? 37 00 0c 05 28 c9 }
		$S_4_3d18 = { 3d 02 07 00 71 10 ?? ?? 02 00 0c 00 11 00 12 00 28 fe }
		$S_8_13114 = { 13 00 0a 00 23 00 ?? ?? 12 01 1a 02 ?? ?? 4d 02 00 01 12 11 1a 02 ?? ?? 4d 02 00 01 12 21 1a 02 ?? ?? 4d 02 00 01 12 31 1a 02 ?? ?? 4d 02 00 01 12 41 1a 02 ?? ?? 4d 02 00 01 12 51 1a 02 ?? ?? 4d 02 00 01 12 61 1a 02 ?? ?? 4d 02 00 01 12 71 1a 02 ?? ?? 4d 02 00 01 13 01 08 00 1a 02 ?? ?? 4d 02 00 01 13 01 09 00 1a 02 ?? ?? 4d 02 00 01 11 00 }
		$S_4_12340 = { 12 01 54 a7 ?? ?? 1a 08 ?? ?? 12 09 6e 30 ?? ?? 87 09 0c 01 39 01 18 00 22 07 ?? ?? 1a 08 ?? ?? 70 20 ?? ?? 87 00 27 07 0d 03 62 07 ?? ?? 1a 08 ?? ?? 71 30 ?? ?? 87 03 38 01 05 00 72 10 ?? 02 01 00 0e 00 62 07 ?? ?? 22 08 ?? ?? 70 10 ?? ?? 08 00 1a 09 ?? ?? 6e 20 ?? ?? 98 00 0c 08 72 10 ?? 02 01 00 0a 09 6e 20 ?? ?? 98 00 0c 08 6e 10 ?? ?? 08 00 0c 08 71 20 ?? ?? 87 00 72 10 ?? 02 01 00 0a 07 38 07 61 00 1a 07 ?? ?? 72 20 ?? 02 71 00 0a 07 72 20 ?? 02 71 00 0c 04 22 00 ?? ?? 70 20 ?? ?? 40 00 1a 07 ?? ?? 72 20 ?? 02 71 00 0a 07 72 20 ?? 02 71 00 0c 06 70 20 ?? ?? 4a 00 0c 05 6e 20 ?? ?? 50 00 1a 07 ?? ?? 72 20 ?? 02 71 00 0a 07 72 20 ?? 02 71 00 0b 08 6e 30 ?? ?? 80 09 71 10 ?? ?? 06 00 0a 07 39 07 1c 00 12 17 6e 20 ?? ?? 70 00 6e 10 ?? ?? 00 00 0a 07 38 07 14 00 6e 20 ?? ?? 60 00 54 a7 ?? ?? 6e 30 ?? ?? 47 00 28 b5 0d 07 38 01 05 00 72 10 ?? 02 01 00 27 07 12 07 28 e6 54 a7 ?? ?? 6e 30 ?? ?? 47 05 0c 02 54 a7 ?? ?? 71 30 ?? ?? 27 02 0c 07 6e 20 ?? ?? 70 00 28 e2 38 01 7e ff 72 10 ?? 02 01 00 29 00 79 ff }
		$S_4_1a106 = { 1a 00 ?? ?? 69 00 ?? ?? 71 00 ?? ?? 00 00 0a 00 38 00 18 00 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 12 10 0f 00 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 28 ea }
		$S_4_12228 = { 12 01 22 02 ?? ?? 22 06 ?? ?? 22 07 ?? ?? 70 20 ?? ?? 97 00 70 20 ?? ?? 76 00 70 20 ?? ?? 62 00 6e 10 ?? ?? 02 00 0c 04 38 04 32 00 1a 06 ?? ?? 6e 20 ?? ?? 64 00 0a 06 39 06 0a 00 1a 06 ?? ?? 6e 20 ?? ?? 64 00 0a 06 38 06 ec ff 1a 00 ?? ?? 1a 06 ?? ?? 6e 20 ?? ?? 64 00 0a 06 1a 07 ?? ?? 6e 10 ?? ?? 07 00 0a 07 b0 76 13 07 22 00 6e 20 ?? ?? 74 00 0a 07 6e 30 ?? ?? 64 07 0c 05 38 02 05 00 6e 10 ?? ?? 02 00 07 21 11 05 38 02 05 00 6e 10 ?? ?? 02 00 07 21 12 05 28 f8 0d 06 07 21 28 fc 0d 03 62 06 ?? ?? 1a 07 ?? ?? 71 30 ?? ?? 76 03 38 01 f3 ff 6e 10 ?? ?? 01 00 28 ee 0d 06 28 ec 0d 06 38 01 05 00 6e 10 ?? ?? 01 00 27 06 0d 06 28 db 0d 07 28 fc 0d 06 07 21 28 f4 0d 03 07 21 28 e1 }
		$S_4_12346 = { 12 17 71 00 ?? ?? 00 00 0a 08 72 20 ?? 02 8b 00 0c 01 6e 20 ?? ?? 1a 00 0c 00 1f 00 ?? ?? 22 04 ?? ?? 70 10 ?? ?? 04 00 71 00 ?? ?? 00 00 0a 08 72 20 ?? 02 8b 00 0c 08 6e 20 ?? ?? 84 00 71 00 ?? ?? 00 00 0a 08 72 20 ?? 02 8b 00 0a 08 33 78 5a 00 6e 20 ?? ?? 74 00 71 00 ?? ?? 00 00 0a 07 72 20 ?? 02 7b 00 0b 08 6e 30 ?? ?? 84 09 71 00 ?? ?? 00 00 0a 07 72 20 ?? 02 7b 00 0c 07 6e 20 ?? ?? 74 00 71 00 ?? ?? 00 00 0a 07 72 20 ?? 02 7b 00 0c 05 71 00 ?? ?? 00 00 0a 07 72 20 ?? 02 7b 00 0c 03 71 00 ?? ?? 00 00 0a 07 72 20 ?? 02 7b 00 0c 07 6e 20 ?? ?? 74 00 54 a7 ?? ?? 6e 10 ?? ?? 04 00 0c 08 1a 09 ?? ?? 6e 30 ?? ?? 87 09 0c 07 6e 20 ?? ?? 74 00 71 10 ?? ?? 05 00 0a 07 39 07 13 00 1a 07 ?? ?? 6e 20 ?? ?? 75 00 0a 07 39 07 0b 00 6e 20 ?? ?? 54 00 6e 20 ?? ?? 40 00 11 04 12 07 28 a7 71 10 ?? ?? 03 00 0a 07 39 07 f6 ff 1a 07 ?? ?? 6e 20 ?? ?? 73 00 0a 07 39 07 ee ff 1a 07 ?? ?? 6e 20 ?? ?? 73 00 0a 07 38 07 e6 ff 70 20 ?? ?? 3a 00 0c 06 38 06 e0 ff 6e 20 ?? ?? 64 00 28 db 0d 02 62 07 ?? ?? 1a 08 ?? ?? 71 30 ?? ?? 87 02 12 04 28 d4 }
		$S_4_54174 = { 54 75 ?? ?? 1a 06 ?? ?? 71 20 ?? ?? 65 00 12 02 12 03 12 00 54 75 ?? ?? 6e 10 ?? 01 05 00 0c 05 70 20 ?? ?? 87 00 0c 06 6e 20 ?? 01 65 00 0c 02 71 10 ?? 03 02 00 0c 00 22 04 ?? ?? 70 10 ?? ?? 04 00 62 05 ?? 00 13 06 14 00 6e 40 ?? 03 50 46 6e 10 ?? ?? 04 00 0c 05 6e 10 ?? ?? 02 00 6e 10 ?? ?? 04 00 07 43 11 05 0d 01 12 05 6e 10 ?? ?? 02 00 6e 10 ?? ?? 03 00 28 f7 0d 06 28 f5 0d 05 6e 10 ?? ?? 02 00 6e 10 ?? ?? 03 00 27 05 0d 06 28 e7 0d 06 28 e8 0d 06 28 ed 0d 06 28 f5 0d 06 28 f6 0d 05 07 43 28 ed 0d 01 07 43 28 df }
		$S_4_5292 = { 52 a1 ?? ?? 72 20 ?? 02 1b 00 0c 00 52 a1 ?? ?? 72 20 ?? 02 1b 00 0c 03 52 a1 ?? ?? 72 20 ?? 02 1b 00 0c 04 52 a1 ?? ?? 72 20 ?? 02 1b 00 0c 05 52 a1 ?? ?? 72 20 ?? 02 1b 00 0b 06 52 a1 ?? ?? 72 20 ?? 02 1b 00 0b 08 22 01 ?? ?? 71 10 ?? ?? 00 00 0c 02 76 09 ?? ?? 01 00 11 01 }
		$S_4_12198 = { 12 00 22 01 ?? ?? 22 04 ?? ?? 22 05 ?? ?? 70 20 ?? ?? 75 00 70 20 ?? ?? 54 00 70 20 ?? ?? 41 00 6e 10 ?? ?? 01 00 0c 03 38 03 23 00 1a 04 ?? 07 6e 20 ?? ?? 43 00 0a 04 38 04 f4 ff 13 04 3e 00 6e 20 ?? ?? 43 00 0a 04 d8 04 04 01 13 05 3c 00 6e 20 ?? ?? 53 00 0a 05 6e 30 ?? ?? 43 05 0c 04 38 01 05 00 6e 10 ?? ?? 01 00 07 10 11 04 38 01 05 00 6e 10 ?? ?? 01 00 07 10 12 04 28 f8 0d 04 07 10 28 fc 0d 02 62 04 ?? ?? 1a 05 ?? ?? 71 30 ?? ?? 54 02 38 00 f3 ff 6e 10 ?? ?? 00 00 28 ee 0d 04 28 ec 0d 04 38 00 05 00 6e 10 ?? ?? 00 00 27 04 0d 05 28 db 0d 05 28 fc 0d 04 07 10 28 f4 0d 02 07 10 28 e1 }
		$S_4_1a38 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_5524 = { 55 20 ?? ?? 38 00 02 00 54 20 ?? ?? 1a 01 ?? ?? 71 20 ?? ?? 10 00 0e 00 }
		$S_4_1a36 = { 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 1a 00 ?? ?? 69 00 ?? ?? 12 10 0f 00 }
		$S_8_1a34 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 67 00 ?? ?? 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 67 00 ?? ?? 0e 00 }
		$S_4_6e624 = { 6e 10 ?? ?? 0c 00 0c 01 71 10 ?? ?? 01 00 0a 06 38 06 04 00 12 06 0f 06 6e 10 ?? ?? 0c 00 0c 05 39 05 14 00 22 06 ?? ?? 1a 07 ?? ?? 70 20 ?? ?? 76 00 27 06 0d 02 62 06 ?? ?? 1a 07 ?? ?? 71 30 ?? ?? 76 02 12 06 28 e8 62 06 ?? ?? 6e 20 ?? ?? 65 00 0a 06 39 06 0a 00 22 06 ?? ?? 1a 07 ?? ?? 70 20 ?? ?? 76 00 27 06 22 06 ?? ?? 70 10 ?? ?? 06 00 70 10 ?? ?? 0b 00 0c 07 6e 20 ?? ?? 76 00 0c 06 1a 07 ?? ?? 6e 20 ?? ?? 76 00 0c 06 6e 10 ?? ?? 06 00 0c 00 12 03 62 06 ?? ?? 22 07 ?? ?? 70 10 ?? ?? 07 00 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 20 ?? ?? 07 00 0c 07 6e 10 ?? ?? 07 00 0c 07 71 20 ?? ?? 76 00 6e 10 ?? ?? 0c 00 0a 06 38 06 81 00 54 b6 ?? ?? 72 10 ?? ?? 06 00 0a 06 39 06 0a 00 22 06 ?? ?? 1a 07 ?? ?? 70 20 ?? ?? 76 00 27 06 54 b6 ?? ?? 72 10 ?? ?? 06 00 0c 04 1f 04 ?? ?? 62 06 ?? ?? 22 07 ?? ?? 70 10 ?? ?? 07 00 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 10 ?? ?? 04 00 0c 08 6e 20 ?? ?? 87 00 0c 07 6e 10 ?? ?? 07 00 0c 07 71 20 ?? ?? 76 00 22 06 ?? ?? 70 10 ?? ?? 06 00 6e 20 ?? ?? 06 00 0c 06 6e 10 ?? ?? 04 00 0c 07 6e 20 ?? ?? 76 00 0c 06 1a 07 ?? ?? 6e 20 ?? ?? 76 00 0c 06 6e 10 ?? ?? 04 00 0c 07 6e 20 ?? ?? 76 00 0c 06 1a 07 ?? ?? 6e 20 ?? ?? 76 00 0c 06 6e 10 ?? ?? 06 00 0c 03 62 06 ?? ?? 22 07 ?? ?? 70 10 ?? ?? 07 00 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 20 ?? ?? 37 00 0c 07 6e 10 ?? ?? 07 00 0c 07 71 20 ?? ?? 76 00 39 03 4d 00 22 06 ?? ?? 1a 07 ?? ?? 70 20 ?? ?? 76 00 27 06 54 b6 ?? ?? 6e 20 ?? ?? c6 00 0c 04 39 04 14 00 54 b6 ?? ?? 62 07 ?? ?? 1a 08 ?? ?? 1a 09 ?? ?? 6e 10 ?? ?? 0b 00 0c 0a 71 5a ?? ?? 76 98 12 16 29 00 0a ff 62 06 ?? ?? 22 07 ?? ?? 70 10 ?? ?? 07 00 1a 08 ?? ?? 6e 20 ?? ?? 87 00 0c 07 6e 10 ?? ?? 04 00 0c 08 6e 20 ?? ?? 87 00 0c 07 6e 10 ?? ?? 07 00 0c 07 71 20 ?? ?? 76 00 6e 10 ?? ?? 04 00 0c 06 6e 10 ?? ?? 04 00 0c 07 71 30 ?? ?? 60 07 0c 03 28 9c 12 06 6e 20 ?? ?? 6c 00 54 b6 ?? ?? 6e 5e ?? ?? 6b 3c 12 16 29 00 d5 fe }
		$S_4_08662 = { 08 00 12 00 54 02 ?? ?? 08 00 14 00 72 20 ?? ?? 02 00 0a 02 38 02 0f 00 08 00 12 00 54 02 ?? ?? 08 00 14 00 72 20 ?? ?? 02 00 0c 02 1f 02 ?? ?? 11 02 39 13 29 00 22 02 ?? ?? 1a 03 ?? ?? 70 20 ?? ?? 32 00 27 02 0d 0d 08 00 12 00 54 02 ?? ?? 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 08 00 14 00 6e 20 ?? ?? 03 00 0c 03 6e 10 ?? ?? 03 00 0c 03 71 20 ?? ?? 32 00 12 02 28 d7 39 14 0a 00 22 02 ?? ?? 1a 03 ?? ?? 70 20 ?? ?? 32 00 27 02 22 02 ?? ?? 70 10 ?? ?? 02 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0c 02 08 00 14 00 6e 20 ?? ?? 02 00 0c 02 6e 10 ?? ?? 02 00 0c 05 1a 03 ?? ?? 08 00 12 00 54 04 ?? ?? 12 06 12 07 12 08 12 09 12 0a 08 02 13 00 74 09 ?? ?? 02 00 0c 0b 39 0b 0a 00 22 02 ?? ?? 1a 03 ?? ?? 70 20 ?? ?? 32 00 27 02 72 10 ?? 02 0b 00 0a 02 39 02 23 00 22 02 ?? ?? 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 08 00 14 00 6e 20 ?? ?? 03 00 0c 03 1a 04 ?? 01 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 03 70 20 ?? ?? 32 00 27 02 1a 02 ?? ?? 72 20 ?? 02 2b 00 0a 02 72 20 ?? 02 2b 00 0c 10 22 02 ?? ?? 70 10 ?? ?? 02 00 1a 03 ?? 05 6e 20 ?? ?? 32 00 0c 02 08 00 10 00 6e 20 ?? ?? 02 00 0c 02 6e 10 ?? ?? 02 00 0c 0c 22 02 ?? ?? 70 10 ?? ?? 02 00 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0c 02 08 00 14 00 6e 20 ?? ?? 02 00 0c 02 1a 03 ?? ?? 6e 20 ?? ?? 32 00 0c 02 6e 10 ?? ?? 02 00 0c 0e 12 02 71 30 ?? ?? ec 02 0c 0f 38 0f 05 00 21 f2 3c 02 1b 00 22 02 ?? ?? 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? f3 00 0c 03 6e 10 ?? ?? 03 00 0c 03 70 20 ?? ?? 32 00 27 02 21 f2 12 13 37 32 26 00 08 00 12 00 54 02 ?? ?? 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? e3 00 0c 03 1a 04 ?? 02 6e 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? f3 00 0c 03 6e 10 ?? ?? 03 00 0c 03 71 20 ?? ?? 32 00 22 02 ?? ?? 70 10 ?? ?? 02 00 6e 20 ?? ?? c2 00 0c 02 12 03 46 03 0f 03 6e 20 ?? ?? 32 00 0c 02 6e 10 ?? ?? 02 00 0c 11 08 00 12 00 54 02 ?? ?? 08 00 14 00 08 01 11 00 72 30 ?? ?? 02 01 08 02 11 00 29 00 cf fe }
		$S_4_1240 = { 12 03 54 80 ?? ?? 6e 10 ?? ?? 08 00 0c 01 6e 10 ?? ?? 08 00 0c 02 07 34 07 35 07 36 07 37 74 08 ?? ?? 00 00 0c 00 11 00 }
		$S_4_5452 = { 54 42 ?? ?? 6e 10 ?? ?? 02 00 0c 01 72 10 ?? ?? 01 00 0c 02 5b 42 ?? ?? 6f 20 ?? ?? 54 00 0c 02 11 02 0d 00 62 02 ?? ?? 1a 03 ?? ?? 71 30 ?? ?? 32 00 28 f3 }
		$S_4_2222 = { 22 00 ?? ?? 54 21 ?? ?? 70 20 ?? ?? 10 00 5b 20 ?? ?? 12 10 0f 00 }
		$S_4_12294 = { 12 0e 1a 09 ?? ?? 1a 0b ?? ?? 1a 0a ?? ?? 08 00 10 00 54 01 ?? ?? 1a 02 ?? ?? 12 33 23 33 ?? ?? 12 04 1a 05 ?? ?? 4d 05 03 04 12 14 1a 05 ?? ?? 4d 05 03 04 12 24 1a 05 ?? ?? 4d 05 03 04 22 04 ?? ?? 70 10 ?? ?? 04 00 1a 05 ?? ?? 6e 20 ?? ?? 54 00 0c 04 08 00 11 00 6e 20 ?? ?? 04 00 0c 04 1a 05 ?? ?? 6e 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0c 04 12 05 12 06 12 07 12 08 74 08 ?? ?? 01 00 0c 0e 38 0e 35 00 72 10 ?? 02 0e 00 0a 01 38 01 2f 00 22 0d ?? ?? 08 00 11 00 70 20 ?? ?? 0d 00 1a 01 ?? ?? 72 20 ?? 02 1e 00 0a 01 72 20 ?? 02 1e 00 0c 01 6e 20 ?? ?? 1d 00 1a 01 ?? ?? 72 20 ?? 02 1e 00 0a 01 72 20 ?? 02 1e 00 0a 0c 12 21 33 1c 0c 00 12 11 6e 20 ?? ?? 1d 00 38 0e 05 00 72 10 ?? 02 0e 00 11 0d 12 01 28 f6 38 0e 05 00 72 10 ?? 02 0e 00 12 0d 28 f7 0d 0f 62 01 ?? ?? 1a 02 ?? ?? 71 30 ?? ?? 21 0f 38 0e f6 ff 72 10 ?? 02 0e 00 28 f1 0d 01 38 0e 05 00 72 10 ?? 02 0e 00 27 01 }
		$S_4_1692 = { 16 06 ff ff 54 a3 ?? ?? 13 08 03 03 6e 30 ?? ?? 3a 08 6e 10 ?? ?? 0a 00 0c 02 21 28 12 03 35 83 1e 00 46 01 02 03 54 a9 ?? ?? 71 20 ?? ?? 19 00 0c 09 71 10 ?? ?? 09 00 0b 04 31 09 04 06 3d 09 03 00 04 46 d8 03 03 01 28 eb 0d 00 54 a3 ?? ?? 1a 08 ?? ?? 71 30 ?? ?? 83 00 10 06 }
		$S_4_12214 = { 12 01 6e 10 ?? ?? 06 00 0a 03 39 03 1f 00 6e 10 ?? ?? 06 00 22 03 ?? ?? 1a 04 ?? ?? 70 20 ?? ?? 43 00 27 03 0d 00 54 63 ?? ?? 1a 04 ?? ?? 71 30 ?? ?? 43 00 38 01 05 00 72 10 ?? 02 01 00 6e 10 ?? ?? 06 00 12 02 11 02 6e 20 ?? ?? 76 00 6e 20 ?? ?? 76 00 0c 01 39 01 14 00 22 03 ?? ?? 1a 04 ?? ?? 70 20 ?? ?? 43 00 27 03 0d 03 38 01 05 00 72 10 ?? 02 01 00 6e 10 ?? ?? 06 00 27 03 54 63 ?? ?? 22 04 ?? ?? 70 10 ?? ?? 04 00 1a 05 ?? ?? 6e 20 ?? ?? 54 00 0c 04 72 10 ?? 02 01 00 0a 05 6e 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0c 04 71 20 ?? ?? 43 00 6e 20 ?? ?? 16 00 6e 30 ?? ?? 16 08 0c 02 38 01 05 00 72 10 ?? 02 01 00 6e 10 ?? ?? 06 00 28 b9 }
		$S_4_12350 = { 12 02 54 c0 ?? ?? 62 01 ?? 00 1a 03 ?? ?? 12 14 23 44 ?? ?? 12 05 6e 10 ?? ?? 0d 00 0c 0b 4d 0b 04 05 07 25 74 06 ?? 01 00 00 0c 06 38 06 98 00 72 10 ?? 02 06 00 0a 00 38 00 8f 00 71 10 ?? ?? 06 00 0a 00 72 20 ?? 02 06 00 0c 0a 71 10 ?? ?? 06 00 0a 00 72 20 ?? 02 06 00 0c 07 71 10 ?? ?? 06 00 0a 00 72 20 ?? 02 06 00 0a 08 1a 00 ?? ?? 6e 20 ?? ?? 0a 00 0a 00 38 00 2a 00 54 c0 ?? ?? 71 10 ?? 06 08 00 0a 01 6e 20 ?? 01 10 00 0c 00 6e 30 ?? ?? 0d 07 28 cd 0d 09 54 c0 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 0c 01 6e 20 ?? ?? d1 00 0c 01 6e 10 ?? ?? 01 00 0c 01 71 30 ?? ?? 10 09 28 b3 1a 00 ?? ?? 6e 20 ?? ?? 0a 00 0a 00 38 00 10 00 54 c0 ?? ?? 71 10 ?? 06 08 00 0a 01 6e 20 ?? 01 10 00 0c 00 6e 30 ?? ?? 0d 07 28 9d 1a 00 ?? ?? 6e 20 ?? ?? 0a 00 0a 00 38 00 10 00 54 c0 ?? ?? 71 10 ?? 06 08 00 0a 01 6e 20 ?? 01 10 00 0c 00 6e 30 ?? ?? 0d 07 28 87 1a 00 ?? ?? 6e 20 ?? ?? 0a 00 0a 00 38 00 80 ff 54 c0 ?? ?? 71 10 ?? ?? 07 00 0a 01 6e 20 ?? ?? 10 00 0c 00 1f 00 ?? ?? 6e 20 ?? ?? 0d 00 29 00 6f ff 72 10 ?? 02 06 00 0e 00 }
		$S_4_22108 = { 22 01 ?? ?? 70 20 ?? ?? 61 00 6e 10 ?? ?? 01 00 0a 02 38 02 0a 00 6e 30 ?? ?? 65 06 0c 02 6e 20 ?? ?? 21 00 11 01 38 06 ff ff 1a 02 ?? ?? 6e 20 ?? ?? 26 00 0a 02 38 02 f7 ff 54 52 ?? ?? 1a 03 ?? ?? 6e 20 ?? ?? 36 00 0c 03 12 14 46 03 03 04 6e 20 ?? ?? 32 00 0c 00 38 00 e6 ff 6e 10 ?? ?? 00 00 0c 02 6e 20 ?? ?? 21 00 28 dd }
		$S_4_54100 = { 54 40 ?? ?? 39 00 21 00 70 10 ?? ?? 04 00 0c 00 5b 40 ?? ?? 54 40 ?? ?? 39 00 17 00 54 40 ?? ?? 71 10 ?? ?? 00 00 0c 00 6e 10 ?? ?? 04 00 0c 01 6e 20 ?? ?? 10 00 22 00 ?? ?? 1a 01 ?? ?? 70 20 ?? ?? 10 00 27 00 1a 00 ?? ?? 12 11 23 11 ?? ?? 12 02 54 43 ?? ?? 4d 03 01 02 71 20 ?? ?? 10 00 0c 00 11 00 }
		$S_12_6032 = { 60 00 ?? ?? 12 f1 33 10 0a 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 67 00 ?? ?? 60 00 ?? ?? 0f 00 }
		$S_4_6e84 = { 6e 10 ?? ?? 08 00 0c 03 6e 10 ?? ?? 08 00 0c 04 12 05 6e 10 ?? ?? 08 00 0c 06 38 06 0e 00 6e 10 ?? ?? 08 00 0c 00 6e 10 ?? ?? 00 00 0a 00 6e 20 ?? ?? 07 00 0c 05 6e 10 ?? ?? 07 00 0c 02 54 70 ?? ?? 6e 10 ?? ?? 07 00 0c 01 74 06 ?? 01 00 00 0c 00 11 00 }
		$S_4_12366 = { 12 0d 12 0a 12 0b 54 e0 ?? ?? 1a 01 ?? ?? 12 12 23 22 ?? ?? 12 03 1a 04 ?? ?? 4d 04 02 03 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? f3 00 0c 03 6e 10 ?? ?? 03 00 0c 03 12 04 12 05 12 06 12 07 74 08 ?? ?? 00 00 0c 0a 38 0a 62 00 72 10 ?? 02 0a 00 0a 00 38 00 5c 00 1a 00 ?? ?? 72 20 ?? 02 0a 00 0a 00 72 20 ?? 02 0a 00 0c 0c 54 e0 ?? ?? 1a 01 ?? ?? 12 12 23 22 ?? ?? 12 03 1a 04 ?? ?? 4d 04 02 03 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? c3 00 0c 03 6e 10 ?? ?? 03 00 0c 03 12 04 12 05 12 06 12 07 74 08 ?? ?? 00 00 0c 0b 38 0b 29 00 72 10 ?? 02 0b 00 0a 00 38 00 23 00 1a 00 ?? ?? 72 20 ?? 02 0b 00 0a 00 72 20 ?? 02 0b 00 0c 09 71 10 ?? ?? 09 00 0a 00 39 00 13 00 54 e0 ?? ?? 71 20 ?? ?? 90 00 0c 00 38 0a 05 00 72 10 ?? 02 0a 00 38 0b 05 00 72 10 ?? 02 0b 00 11 00 38 0a 05 00 72 10 ?? 02 0a 00 38 0b 05 00 72 10 ?? 02 0b 00 07 d0 28 f4 0d 08 54 e0 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 08 38 0a 05 00 72 10 ?? 02 0a 00 38 0b f1 ff 72 10 ?? 02 0b 00 28 ec 0d 00 38 0a 05 00 72 10 ?? 02 0a 00 38 0b 05 00 72 10 ?? 02 0b 00 27 00 }
		$S_8_1a128 = { 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 1a 00 ?? ?? 72 20 ?? 02 02 00 0a 00 71 10 ?? ?? 00 00 0e 00 }
		$S_4_5442 = { 54 20 ?? ?? 1a 01 ?? ?? 71 20 ?? ?? 10 00 0a 00 38 00 0a 00 1a 00 ?? ?? 71 10 ?? 05 00 00 0c 00 11 00 0d 00 62 00 ?? ?? 28 fc }
		$S_4_5440 = { 54 20 ?? ?? 38 00 11 00 38 03 0f 00 54 20 ?? ?? 6e 10 ?? ?? 03 00 0c 01 6e 20 ?? ?? 12 00 0c 01 6e 30 ?? ?? 10 03 0e 00 }
		$S_4_5446 = { 54 21 ?? ?? 6e 20 ?? ?? 31 00 0a 01 38 01 0b 00 54 21 ?? ?? 6e 20 ?? ?? 31 00 0c 01 1f 01 ?? ?? 11 01 6e 30 ?? ?? 32 04 0c 00 07 01 28 fa }
		$S_4_6f86 = { 6f 10 ?? ?? 04 00 0a 02 38 02 25 00 1a 02 ?? ?? 6e 20 ?? ?? 24 00 0c 00 38 00 10 00 22 02 ?? ?? 54 43 ?? ?? 70 30 ?? ?? 32 00 5b 42 ?? ?? 54 42 ?? ?? 6e 10 ?? ?? 02 00 70 10 ?? ?? 04 00 12 12 0f 02 0d 01 62 02 ?? ?? 1a 03 ?? ?? 71 30 ?? ?? 32 01 12 02 28 f6 }
		$S_4_12416 = { 12 08 71 00 ?? ?? 00 00 0a 09 72 20 ?? 02 9d 00 0c 06 6e 20 ?? ?? 6c 00 0c 00 1f 00 ?? ?? 22 04 ?? ?? 70 10 ?? ?? 04 00 71 00 ?? ?? 00 00 0a 09 72 20 ?? 02 9d 00 0c 09 6e 20 ?? ?? 94 00 71 00 ?? ?? 00 00 0a 09 72 20 ?? 02 9d 00 0c 09 6e 20 ?? ?? 94 00 6e 10 ?? ?? 04 00 0c 09 70 20 ?? ?? 9c 00 0a 09 6e 20 ?? ?? 94 00 71 00 ?? ?? 00 00 0a 09 72 20 ?? 02 9d 00 0b 0a 6e 30 ?? ?? a4 0b 71 00 ?? ?? 00 00 0a 09 72 20 ?? 02 9d 00 0c 09 6e 20 ?? ?? 94 00 71 00 ?? ?? 00 00 0a 09 72 20 ?? 02 9d 00 0c 09 6e 20 ?? ?? 94 00 71 00 ?? ?? 00 00 0a 09 72 20 ?? 02 9d 00 0c 09 6e 20 ?? ?? 94 00 71 00 ?? ?? 00 00 0a 09 72 20 ?? 02 9d 00 0c 09 6e 20 ?? ?? 94 00 71 00 ?? ?? 00 00 0a 09 72 20 ?? 02 9d 00 0c 09 6e 20 ?? ?? 94 00 6e 10 ?? ?? 04 00 0a 09 38 09 09 00 6e 10 ?? ?? 04 00 0c 09 6e 20 ?? ?? 94 00 12 02 12 03 6e 10 ?? ?? 04 00 0a 09 38 09 0e 00 54 c9 ?? ?? 6e 20 ?? ?? 94 00 0c 05 38 05 06 00 6e 20 ?? ?? 54 00 12 12 6e 10 ?? ?? 04 00 0a 09 38 09 0c 00 6e 10 ?? ?? 04 00 0c 07 6e 20 ?? ?? 74 00 38 07 1d 00 12 12 39 02 12 00 6e 10 ?? ?? 04 00 0a 09 38 09 0c 00 54 c9 ?? ?? 6e 10 ?? ?? 0e 00 0a 0a 6e 5a ?? ?? 9c 40 0a 03 38 00 07 00 39 03 05 00 6e 20 ?? ?? 40 00 11 04 12 02 28 e5 0d 01 54 c9 ?? ?? 62 0a ?? ?? 1a 0b ?? ?? 71 51 ?? ?? a9 8b 07 84 28 f2 }
		$S_4_71116 = { 71 00 ?? ?? 00 00 0a 03 72 20 ?? 02 36 00 0c 01 71 00 ?? ?? 00 00 0a 03 72 20 ?? 02 36 00 0c 02 54 53 ?? ?? 72 10 ?? ?? 03 00 0c 03 72 10 ?? ?? 03 00 0a 04 38 04 1e 00 72 10 ?? ?? 03 00 0c 00 1f 00 ?? ?? 71 10 ?? ?? 00 00 0c 04 6e 20 ?? ?? 42 00 0a 04 38 04 ec ff 71 10 ?? ?? 00 00 0c 04 6e 20 ?? ?? 41 00 0a 04 38 04 e2 ff 12 13 0f 03 12 03 28 fe }
		$S_4_12208 = { 12 0a 12 08 54 b0 ?? ?? 1a 01 ?? ?? 12 22 23 22 ?? ?? 12 03 1a 04 ?? ?? 4d 04 02 03 12 13 1a 04 ?? ?? 4d 04 02 03 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 20 ?? ?? c3 00 0c 03 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 03 12 04 12 05 12 06 12 07 74 08 ?? ?? 00 00 0c 08 38 08 18 00 72 10 ?? 02 08 00 0a 00 38 00 12 00 1a 00 ?? ?? 72 20 ?? 02 08 00 0a 00 72 20 ?? 02 08 00 0c 00 38 08 05 00 72 10 ?? 02 08 00 11 00 38 08 05 00 72 10 ?? 02 08 00 07 a0 28 f9 0d 09 54 b0 ?? ?? 1a 01 ?? ?? 71 30 ?? ?? 10 09 38 08 f6 ff 72 10 ?? 02 08 00 28 f1 0d 00 38 08 05 00 72 10 ?? 02 08 00 27 00 }
		$S_4_12160 = { 12 13 12 04 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 02 ?? ?? 12 25 23 55 ?? ?? 12 06 71 10 ?? ?? 0a 00 0c 07 4d 07 05 06 12 16 4d 09 05 06 71 20 ?? ?? 52 00 0c 02 6e 20 ?? ?? 20 00 22 05 ?? ?? 12 06 12 02 23 22 ?? ?? 6e 20 ?? ?? 20 00 0c 02 1f 02 ?? ?? 70 30 ?? ?? 65 02 71 10 ?? ?? 05 00 01 32 0f 02 0d 01 54 82 ?? ?? 22 03 ?? ?? 70 10 ?? ?? 03 00 1a 05 ?? ?? 6e 20 ?? ?? 53 00 0c 03 71 10 ?? ?? 09 00 0c 05 6e 20 ?? ?? 53 00 0c 03 6e 10 ?? ?? 03 00 0c 03 71 20 ?? ?? 32 00 01 42 28 e1 }
		$S_4_12204 = { 12 16 22 04 ?? ?? 70 10 ?? ?? 04 00 6e 10 ?? ?? 09 00 0c 05 6e 20 ?? ?? 54 00 0c 04 22 05 ?? ?? 70 20 ?? ?? a5 00 6e 10 ?? ?? 05 00 0c 05 6e 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0c 02 71 30 ?? ?? 2a 06 0c 03 22 01 ?? ?? 70 20 ?? ?? 31 00 6e 10 ?? ?? 01 00 0a 04 39 04 0a 00 22 04 ?? ?? 1a 05 ?? ?? 70 20 ?? ?? 54 00 27 04 70 40 ?? ?? a7 23 0c 03 22 00 ?? ?? 70 10 ?? ?? 00 00 38 0c 23 00 1a 04 ?? ?? 71 10 ?? ?? 06 00 0c 05 6e 30 ?? ?? 40 05 1a 04 ?? ?? 6e 10 ?? ?? 09 00 0c 05 6e 30 ?? ?? 40 05 1a 04 ?? ?? 1a 05 00 00 6e 30 ?? ?? 40 05 6e 10 ?? ?? 00 00 0c 04 71 40 ?? ?? b8 43 11 01 6e 20 ?? ?? 39 00 28 e5 }
		$S_4_1d28 = { 1d 01 6f 10 ?? ?? 01 00 54 10 ?? ?? 71 10 ?? ?? 00 00 1e 01 0e 00 0d 00 1e 01 27 00 }
		$S_4_12200 = { 12 0a 12 08 1a 01 ?? ?? 12 10 23 02 ?? ?? 12 00 1a 03 ?? ?? 4d 03 02 00 22 00 ?? ?? 70 10 ?? ?? 00 00 1a 03 ?? ?? 6e 20 ?? ?? 30 00 0c 00 6e 20 ?? ?? c0 00 0c 00 6e 10 ?? ?? 00 00 0c 03 12 04 12 05 12 06 12 07 07 b0 74 08 ?? ?? 00 00 0c 08 72 10 ?? 02 08 00 0a 00 38 00 0c 00 1a 00 ?? ?? 72 20 ?? 02 08 00 0a 00 72 20 ?? 02 08 00 0c 0a 38 08 05 00 72 10 ?? 02 08 00 11 0a 0d 09 62 00 ?? ?? 22 01 ?? ?? 70 10 ?? ?? 01 00 1a 02 ?? ?? 6e 20 ?? ?? 21 00 0c 01 6e 20 ?? ?? c1 00 0c 01 6e 10 ?? ?? 01 00 0c 01 71 30 ?? ?? 10 09 38 08 e6 ff 72 10 ?? 02 08 00 28 e1 0d 00 38 08 05 00 72 10 ?? 02 08 00 27 00 }
		$S_4_13174 = { 13 04 2f 00 6e 20 ?? ?? 49 00 0a 04 d8 04 04 01 13 05 3f 00 6e 20 ?? ?? 59 00 0a 05 6e 30 ?? ?? 49 05 0c 02 22 04 ?? ?? 70 10 ?? ?? 04 00 6e 20 ?? ?? 24 00 0c 04 1a 05 ?? ?? 6e 20 ?? ?? 54 00 0c 04 6e 10 ?? ?? 04 00 0c 01 22 04 ?? ?? 70 10 ?? ?? 04 00 6e 10 ?? ?? 06 00 0c 05 71 10 ?? ?? 05 00 0c 05 6e 20 ?? ?? 54 00 0c 04 1a 05 ?? 05 6e 20 ?? ?? 54 00 0c 04 6e 20 ?? ?? 14 00 0c 04 6e 10 ?? ?? 04 00 0c 03 54 64 ?? ?? 6e 10 ?? ?? 0a 00 0a 05 6e 55 ?? ?? 46 38 0e 00 0d 00 62 04 ?? ?? 1a 05 ?? ?? 71 30 ?? ?? 54 00 28 f7 }
	condition:
		all of them
}
rule Banker2_c {
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
rule koodous_ha: official
{
	meta:
		description = "Ruleset to detect Exaspy RAT"
		sample = "0b8eb5b517a5a841a888d583e0a187983c6028b92634116cfc9bf79d165ac988"
	strings:
		$a = "Sending log to the server. Title: %s Severity: %s Description: %s Module: %s"
		$b = "KEY_LICENSE"
		$c = "Failed to install app in system partition.\n"
		$d = "key_remote_jid"
	condition:
		androguard.url("http://www.exaspy.com/a.apk") or androguard.url("http://api.andr0idservices.com") or all of them
}
rule demo2_a
{
	meta:
		description = "demo"
	strings:
		$a = "Protected by Shield4J"
	    $b = "Spain1"
		$c = "Madrid1"
		$d = "Shield4J"
	condition:
		all of them		
}
rule koodous_ia: official
{
	meta:
		description = "This rule detects the cib bank apk application"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name(/com.cib.bankcib/)
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
rule twittor_a: ccm
{
	meta:
		description = "This rule detects twitoor samples based on ccm"
		sample = "82483f381123dc7c16c282dada2df0cf0c3c0cfa9e8125e3e3941fa57096f44e"
	strings:
		$S_12_1278 = { 12 13 6e 10 ?? 00 05 00 0c 00 6e 20 ?? 00 30 00 6e 20 ?? 00 30 00 6e 20 ?? 00 30 00 1a 01 ?? ?? 6e 20 ?? 00 10 00 12 01 6e 20 ?? 00 10 00 6e 20 ?? 00 30 00 6e 20 ?? 00 30 00 60 01 ?? 00 13 02 11 00 34 21 05 00 6e 20 ?? 00 30 00 0e 00 }
		$S_12_1224 = { 12 01 62 00 ?? ?? 6e 30 ?? 00 02 01 0c 00 72 30 ?? 00 30 01 0a 00 0f 00 }
		$S_12_1634 = { 16 02 ?? ?? 22 01 ?? 00 70 20 ?? ?? 61 00 22 00 ?? ?? 70 10 ?? ?? 00 00 04 24 74 06 ?? ?? 00 00 0e 00 }
		$S_20_2232 = { 22 00 ?? 00 17 02 d8 d6 00 00 16 04 88 13 07 71 07 86 76 07 ?? ?? 00 00 6e 10 ?? ?? 00 00 0e 00 }
		$S_44_12108 = { 12 01 60 00 ?? 00 13 02 13 00 34 20 26 00 22 00 ?? 00 1c 02 ?? ?? 70 30 ?? 00 70 02 15 02 00 10 71 40 ?? 00 17 20 0c 06 1a 00 ?? ?? 6e 20 ?? 00 07 00 0c 00 1f 00 ?? 00 71 00 ?? ?? 00 00 0c 02 6e 10 ?? ?? 02 00 0b 02 17 04 60 ea 00 00 74 07 ?? 00 00 00 0e 00 22 00 ?? 00 1c 01 ?? ?? 70 30 ?? 00 70 01 6e 20 ?? 00 07 00 28 f5 }
		$S_12_13116 = { 13 06 00 01 12 00 70 10 ?? ?? 07 00 23 61 ?? ?? 5b 71 ?? ?? 21 82 01 01 35 61 09 00 54 73 ?? ?? 4b 01 03 01 d8 01 01 01 28 f8 01 01 35 61 23 00 54 73 ?? ?? 44 03 03 01 b0 30 94 03 01 02 48 03 08 03 b0 30 d0 00 00 01 d4 00 00 01 54 73 ?? ?? 44 03 03 00 54 74 ?? ?? 54 75 ?? ?? 44 05 05 01 4b 05 04 00 54 74 ?? ?? 4b 03 04 01 d8 01 01 01 28 de 0e 00 }
		$S_12_12120 = { 12 00 21 93 23 34 ?? ?? 01 01 01 02 35 30 35 00 d8 02 02 01 d4 22 00 01 54 85 ?? ?? 44 05 05 02 b0 51 d4 11 00 01 54 85 ?? ?? 44 05 05 01 54 86 ?? ?? 54 87 ?? ?? 44 07 07 02 4b 07 06 01 54 86 ?? ?? 4b 05 06 02 54 85 ?? ?? 54 86 ?? ?? 44 06 06 02 54 87 ?? ?? 44 07 07 01 b0 76 d4 66 00 01 44 05 05 06 48 06 09 00 b7 65 8d 55 4f 05 04 00 d8 00 00 01 28 cc 11 04 }
		$S_12_6228 = { 62 00 ?? ?? 12 01 6e 30 ?? 00 02 01 0c 00 1a 01 00 00 72 30 ?? 00 30 01 0c 00 11 00 }
	condition:
		all of them
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
rule koodous_ja: official
{
	condition:
		androguard.certificate.sha1("74D37EED750DBA0D962B809A7A2F682C0FB0D4A5") 
}
rule shield4j_a: ccm
{
	meta:
		description = "This rule detects shield4j obfuscator"
	strings:
$S_22_07108 = { 07 a0 07 03 1f 03 ?? ?? 6e 10 ?? ?? 03 00 0a 03 12 34 db 03 03 03 01 39 01 93 01 94 01 41 23 33 ?? ?? 07 32 01 13 d8 01 01 ff 3d 03 1e 00 07 23 01 14 07 05 1f 05 ?? ?? 01 16 12 37 da 06 06 03 01 17 12 18 d8 07 07 01 12 38 da 07 07 03 6e 30 ?? ?? 65 07 0c 05 71 10 ?? ?? 05 00 0a 05 8d 55 4f 05 03 04 28 e0 07 23 07 30 11 00 }
$S_569_078 = { 07 20 12 ?? ?? 10 ?? 00 }
$S_51_0732 = { 07 50 07 61 07 72 07 03 70 10 ?? ?? 03 00 07 03 07 14 5b 34 ?? ?? 07 03 07 24 5b 34 ?? ?? 0e 00 }
$S_139_2222 = { 22 00 ?? ?? 07 02 07 20 07 21 70 10 ?? ?? 01 00 69 00 ?? ?? 0e 00 }
$S_22_6282 = { 62 01 ?? ?? 39 01 23 00 22 01 ?? ?? 07 15 07 51 07 52 70 10 ?? ?? 02 00 07 10 07 01 22 02 ?? ?? 07 25 07 52 07 53 70 10 ?? ?? 03 00 6e 20 ?? ?? 21 00 22 01 ?? ?? 07 15 07 51 07 52 12 03 07 04 70 30 ?? ?? 32 04 69 01 ?? ?? 62 01 ?? ?? 07 10 11 00 }
$S_22_081640 = { 08 01 18 00 12 0f 07 f2 12 0f 07 f3 12 0f 07 f4 12 0f 07 f5 71 00 ?? ?? 00 00 0c 0f 1f 0f ?? ?? 71 10 ?? ?? 0f 00 0c 0f 07 f2 71 00 ?? ?? 00 00 0c 0f 1f 0f ?? ?? 71 10 ?? ?? 0f 00 0c 0f 07 f3 71 00 ?? ?? 00 00 0c 0f 1f 0f ?? ?? 71 10 ?? ?? 0f 00 0c 0f 07 f6 71 00 ?? ?? 00 00 0c 0f 1f 0f ?? ?? 71 10 ?? ?? 0f 00 0c 0f 07 f4 07 3f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 08 10 01 00 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 1f 0f ?? ?? 07 f7 07 7f 6e 10 ?? ?? 0f 00 0a 0f 38 0f 5b 01 07 3f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 08 10 01 00 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 1f 0f ?? ?? 6e 10 ?? ?? 0f 00 0b 0f 04 f8 07 6f 13 10 00 00 02 00 10 00 23 00 ?? ?? 08 10 00 00 74 02 ?? ?? 0f 00 0c 0f 13 10 00 00 02 00 10 00 23 00 ?? ?? 08 10 00 00 74 02 ?? ?? 0f 00 0c 0f 07 fa 07 4f 13 10 02 00 02 00 10 00 23 00 ?? ?? 08 10 00 00 08 17 10 00 08 10 17 00 08 11 17 00 13 12 00 00 08 13 03 00 4d 13 11 12 08 17 10 00 08 10 17 00 08 11 17 00 13 12 01 00 08 13 02 00 4d 13 11 12 74 02 ?? ?? 0f 00 0c 0f 13 10 02 00 02 00 10 00 23 00 ?? ?? 08 10 00 00 08 17 10 00 08 10 17 00 08 11 17 00 13 12 00 00 08 13 01 00 4d 13 11 12 08 17 10 00 08 10 17 00 08 11 17 00 13 12 01 00 71 00 ?? ?? 00 00 0c 13 4d 13 11 12 74 02 ?? ?? 0f 00 0c 0f 07 f5 07 4f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 01 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 08 17 11 00 08 11 17 00 08 12 17 00 13 13 00 00 62 14 ?? ?? 4d 14 12 13 74 03 ?? ?? 0f 00 0c 0f 08 10 05 00 13 11 01 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 08 17 11 00 08 11 17 00 08 12 17 00 13 13 00 00 13 14 00 00 77 01 ?? ?? 14 00 0c 14 4d 14 12 13 74 03 ?? ?? 0f 00 0c 0f 13 0f 40 00 23 ff ?? ?? 07 fb 12 0f 01 fc 01 cf 81 ff 05 11 08 00 31 0f 0f 11 3b 0f 81 00 07 6f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 01 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 08 17 11 00 08 11 17 00 08 12 17 00 13 13 00 00 1c 14 ?? ?? 4d 14 12 13 74 03 ?? ?? 0f 00 0c 0f 08 10 0a 00 13 11 01 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 08 17 11 00 08 11 17 00 08 12 17 00 13 13 00 00 08 14 0b 00 4d 14 12 13 74 03 ?? ?? 0f 00 0c 0f 07 4f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 01 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 08 17 11 00 08 11 17 00 08 12 17 00 13 13 00 00 1c 14 ?? ?? 4d 14 12 13 74 03 ?? ?? 0f 00 0c 0f 08 10 05 00 13 11 01 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 08 17 11 00 08 11 17 00 08 12 17 00 13 13 00 00 08 14 0b 00 4d 14 12 13 74 03 ?? ?? 0f 00 0c 0f 01 cf 08 10 0b 00 08 00 10 00 21 00 02 10 00 00 90 0f 0f 10 01 fc 29 00 7b ff 07 4f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 08 10 05 00 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 71 00 ?? ?? 00 00 0c 0f 1f 0f ?? ?? 71 10 ?? ?? 0f 00 0c 0f 07 f3 07 3f 13 10 01 00 02 00 10 00 23 00 ?? ?? 08 10 00 00 08 17 10 00 08 10 17 00 08 11 17 00 13 12 00 00 08 13 02 00 4d 13 11 12 74 02 ?? ?? 0f 00 0c 0f 07 f6 07 6f 13 10 01 00 02 00 10 00 23 00 ?? ?? 08 10 00 00 08 17 10 00 08 10 17 00 08 11 17 00 13 12 00 00 22 13 ?? ?? 08 17 13 00 08 13 17 00 08 14 17 00 76 01 ?? ?? 14 00 08 14 03 00 71 00 ?? ?? 00 00 0c 15 1f 15 ?? ?? 13 16 00 00 02 00 16 00 23 00 ?? ?? 08 16 00 00 74 03 ?? ?? 14 00 0c 14 08 15 01 00 13 16 00 00 02 00 16 00 23 00 ?? ?? 08 16 00 00 74 03 ?? ?? 14 00 0c 14 74 02 ?? ?? 13 00 0c 13 71 00 ?? ?? 00 00 0c 14 1f 14 ?? ?? 74 02 ?? ?? 13 00 0c 13 74 01 ?? ?? 13 00 0c 13 4d 13 11 12 74 02 ?? ?? 0f 00 0c 0f 07 f7 07 3f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 08 10 01 00 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 07 3f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 08 10 01 00 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 07 3f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 08 10 07 00 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 07 3f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 08 10 07 00 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 0e 00 0d 0f 07 f6 29 00 fd fe 0d 0f 07 f6 07 4f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 08 10 05 00 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 29 00 d8 fe 0d 0f 07 f6 29 00 d4 fe 0d 0f 07 fd 07 4f 71 00 ?? ?? 00 00 0c 10 1f 10 ?? ?? 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 08 10 05 00 13 11 00 00 02 00 11 00 23 00 ?? ?? 08 11 00 00 74 03 ?? ?? 0f 00 0c 0f 07 df 27 0f 0d 0f 07 fe 28 fc 0d 0f 07 f6 28 a8 }
$S_22_0772 = { 07 70 07 81 12 04 07 42 07 04 07 15 6e 20 ?? ?? 54 00 0c 04 07 42 07 24 39 04 17 00 22 04 ?? ?? 07 46 07 64 07 65 70 10 ?? ?? 05 00 27 04 0d 04 07 43 07 04 07 15 6e 20 ?? ?? 54 00 0c 04 07 42 07 24 07 40 11 00 28 fd }
$S_16_07126 = { 07 80 22 02 ?? ?? 07 27 07 72 07 73 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 04 71 10 ?? ?? 04 00 0c 04 70 20 ?? ?? 43 00 71 10 ?? ?? 02 00 0c 02 12 13 23 33 ?? ?? 07 37 07 73 07 74 12 05 1c 06 ?? ?? 4d 06 04 05 6e 20 ?? ?? 32 00 0c 02 12 13 23 33 ?? ?? 07 37 07 73 07 74 12 05 07 06 71 10 ?? ?? 06 00 0c 06 4d 06 04 05 6e 20 ?? ?? 32 00 0c 02 07 20 11 00 0d 02 07 21 12 02 07 20 28 fb }
$S_21_07114 = { 07 b0 1c 09 ?? ?? 1d 09 12 03 07 31 62 03 ?? ?? 39 03 0c 00 62 03 ?? ?? 62 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 69 03 ?? ?? 62 03 ?? ?? 6e 10 ?? ?? 03 00 0c 03 12 04 46 03 03 04 12 04 12 15 23 55 ?? ?? 07 5a 07 a5 07 a6 12 07 07 08 4d 08 06 07 6e 30 ?? ?? 43 05 0c 03 1f 03 ?? ?? 07 31 07 13 07 30 1e 09 11 00 0d 03 07 32 28 fa 0d 00 1e 09 27 00 }
$S_6_07118 = { 07 80 22 02 ?? ?? 07 27 07 72 07 73 1a 04 ?? ?? 71 10 ?? ?? 04 00 0c 04 70 20 ?? ?? 43 00 71 10 ?? ?? 02 00 0c 02 12 13 23 33 ?? ?? 07 37 07 73 07 74 12 05 1c 06 ?? ?? 4d 06 04 05 6e 20 ?? ?? 32 00 0c 02 12 13 23 33 ?? ?? 07 37 07 73 07 74 12 05 07 06 71 10 ?? ?? 06 00 0c 06 4d 06 04 05 6e 20 ?? ?? 32 00 0c 02 07 20 11 00 0d 02 07 21 12 02 07 20 28 fb }
$S_22_082002 = { 08 01 19 00 08 02 1a 00 13 11 00 00 08 03 11 00 13 11 00 00 08 04 11 00 13 11 00 00 08 05 11 00 13 11 00 00 08 06 11 00 71 00 ?? ?? 00 00 0c 11 1f 11 ?? ?? 77 01 ?? ?? 11 00 0c 11 08 03 11 00 71 00 ?? ?? 00 00 0c 11 1f 11 ?? ?? 77 01 ?? ?? 11 00 0c 11 08 05 11 00 71 00 ?? ?? 00 00 0c 11 1f 11 ?? ?? 77 01 ?? ?? 11 00 0c 11 71 00 ?? ?? 00 00 0c 12 1f 12 ?? ?? 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 71 00 ?? ?? 00 00 0c 12 1f 12 ?? ?? 77 01 ?? ?? 12 00 0c 12 71 00 ?? ?? 00 00 0c 13 1f 13 ?? ?? 13 14 00 00 02 00 14 00 23 00 ?? ?? 08 14 00 00 74 03 ?? ?? 12 00 0c 12 13 13 00 00 13 14 00 00 1f 14 ?? ?? 74 03 ?? ?? 12 00 0c 12 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 08 06 11 00 08 11 06 00 39 11 80 00 71 00 ?? ?? 00 00 0c 11 1f 11 ?? ?? 77 01 ?? ?? 11 00 0c 11 08 07 11 00 08 11 07 00 71 00 ?? ?? 00 00 0c 12 1f 12 ?? ?? 13 13 01 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 08 18 13 00 08 13 18 00 08 14 18 00 13 15 00 00 08 16 03 00 4d 16 14 15 74 03 ?? ?? 11 00 0c 11 13 12 00 00 13 13 01 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 08 18 13 00 08 13 18 00 08 14 18 00 13 15 00 00 71 00 ?? ?? 00 00 0c 16 4d 16 14 15 74 03 ?? ?? 11 00 0c 11 08 08 11 00 08 11 05 00 13 12 01 00 02 00 12 00 23 00 ?? ?? 08 12 00 00 08 18 12 00 08 12 18 00 08 13 18 00 13 14 00 00 08 15 03 00 4d 15 13 14 74 02 ?? ?? 11 00 0c 11 13 12 01 00 02 00 12 00 23 00 ?? ?? 08 12 00 00 08 18 12 00 08 12 18 00 08 13 18 00 13 14 00 00 08 15 08 00 4d 15 13 14 74 02 ?? ?? 11 00 0c 11 08 06 11 00 13 11 00 00 08 07 11 00 13 11 00 00 08 08 11 00 13 11 00 00 08 09 11 00 13 11 00 00 08 0a 11 00 08 11 06 00 38 11 3d 02 13 11 01 00 02 0b 11 00 08 11 01 00 02 12 0b 00 d8 0b 0b 01 76 02 ?? ?? 11 00 0c 11 08 0c 11 00 08 11 05 00 13 12 02 00 02 00 12 00 23 00 ?? ?? 08 12 00 00 08 18 12 00 08 12 18 00 08 13 18 00 13 14 00 00 08 15 05 00 4d 15 13 14 08 18 12 00 08 12 18 00 08 13 18 00 13 14 01 00 08 15 03 00 4d 15 13 14 74 02 ?? ?? 11 00 0c 11 08 0d 11 00 08 11 0d 00 13 12 02 00 02 00 12 00 23 00 ?? ?? 08 12 00 00 08 18 12 00 08 12 18 00 08 13 18 00 13 14 00 00 08 15 06 00 4d 15 13 14 08 18 12 00 08 12 18 00 08 13 18 00 13 14 01 00 08 15 0c 00 4d 15 13 14 74 02 ?? ?? 11 00 0c 11 08 07 11 00 08 11 0d 00 13 12 02 00 02 00 12 00 23 00 ?? ?? 08 12 00 00 08 18 12 00 08 12 18 00 08 13 18 00 13 14 00 00 08 15 06 00 4d 15 13 14 08 18 12 00 08 12 18 00 08 13 18 00 13 14 01 00 22 15 ?? ?? 08 18 15 00 08 15 18 00 08 16 18 00 76 01 ?? ?? 16 00 08 16 0c 00 74 02 ?? ?? 15 00 0c 15 71 00 ?? ?? 00 00 0c 16 1f 16 ?? ?? 74 02 ?? ?? 15 00 0c 15 74 01 ?? ?? 15 00 0c 15 4d 15 13 14 74 02 ?? ?? 11 00 0c 11 08 08 11 00 08 11 05 00 71 00 ?? ?? 00 00 0c 12 1f 12 ?? ?? 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 08 0e 11 00 08 11 0e 00 08 12 07 00 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 1f 11 ?? ?? 74 01 ?? ?? 11 00 0a 11 39 11 a0 01 08 11 0e 00 08 12 08 00 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 1f 11 ?? ?? 74 01 ?? ?? 11 00 0a 11 39 11 88 01 71 00 ?? ?? 00 00 0c 11 1f 11 ?? ?? 77 01 ?? ?? 11 00 0c 11 08 09 11 00 08 11 09 00 13 12 01 00 02 00 12 00 23 00 ?? ?? 08 12 00 00 08 18 12 00 08 12 18 00 08 13 18 00 13 14 00 00 08 15 05 00 4d 15 13 14 74 02 ?? ?? 11 00 0c 11 13 12 01 00 02 00 12 00 23 00 ?? ?? 08 12 00 00 08 18 12 00 08 12 18 00 08 13 18 00 13 14 00 00 08 15 07 00 4d 15 13 14 74 02 ?? ?? 11 00 0c 11 08 0a 11 00 08 11 09 00 71 00 ?? ?? 00 00 0c 12 1f 12 ?? ?? 13 13 01 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 08 18 13 00 08 13 18 00 08 14 18 00 13 15 00 00 1c 16 ?? ?? 4d 16 14 15 74 03 ?? ?? 11 00 0c 11 08 12 0a 00 13 13 01 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 08 18 13 00 08 13 18 00 08 14 18 00 13 15 00 00 71 00 ?? ?? 00 00 0c 16 4d 16 14 15 74 03 ?? ?? 11 00 0c 11 71 00 ?? ?? 00 00 0c 11 1f 11 ?? ?? 77 01 ?? ?? 11 00 0c 11 13 12 04 00 02 00 12 00 23 00 ?? ?? 08 12 00 00 08 18 12 00 08 12 18 00 08 13 18 00 13 14 00 00 08 15 03 00 4d 15 13 14 08 18 12 00 08 12 18 00 08 13 18 00 13 14 01 00 08 15 03 00 4d 15 13 14 08 18 12 00 08 12 18 00 08 13 18 00 13 14 02 00 08 15 03 00 4d 15 13 14 08 18 12 00 08 12 18 00 08 13 18 00 13 14 03 00 1c 15 ?? ?? 4d 15 13 14 74 02 ?? ?? 11 00 0c 11 13 12 04 00 02 00 12 00 23 00 ?? ?? 08 12 00 00 08 18 12 00 08 12 18 00 08 13 18 00 13 14 00 00 08 15 05 00 71 00 ?? ?? 00 00 0c 16 1f 16 ?? ?? 13 17 00 00 02 00 17 00 23 00 ?? ?? 08 17 00 00 74 03 ?? ?? 15 00 0c 15 08 16 07 00 13 17 00 00 02 00 17 00 23 00 ?? ?? 08 17 00 00 74 03 ?? ?? 15 00 0c 15 4d 15 13 14 08 18 12 00 08 12 18 00 08 13 18 00 13 14 01 00 08 15 05 00 71 00 ?? ?? 00 00 0c 16 1f 16 ?? ?? 13 17 00 00 02 00 17 00 23 00 ?? ?? 08 17 00 00 74 03 ?? ?? 15 00 0c 15 08 16 06 00 13 17 00 00 02 00 17 00 23 00 ?? ?? 08 17 00 00 74 03 ?? ?? 15 00 0c 15 4d 15 13 14 08 18 12 00 08 12 18 00 08 13 18 00 13 14 02 00 13 15 00 00 4d 15 13 14 08 18 12 00 08 12 18 00 08 13 18 00 13 14 03 00 1c 15 ?? ?? 74 01 ?? ?? 15 00 0c 15 4d 15 13 14 74 02 ?? ?? 11 00 0c 11 1f 11 ?? ?? 08 0c 11 00 08 11 0c 00 08 12 02 00 74 02 ?? ?? 11 00 0c 11 08 04 11 00 08 11 09 00 71 00 ?? ?? 00 00 0c 12 1f 12 ?? ?? 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 08 12 0a 00 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 08 11 07 00 77 01 ?? ?? 11 00 08 11 04 00 08 01 11 00 11 01 0d 11 08 07 11 00 29 00 00 fd 0d 11 08 07 11 00 29 00 7d fd 29 00 93 fd 0d 11 08 0b 11 00 28 e7 0d 11 08 0b 11 00 08 11 09 00 71 00 ?? ?? 00 00 0c 12 1f 12 ?? ?? 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 08 12 0a 00 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 08 11 07 00 77 01 ?? ?? 11 00 28 c1 0d 11 08 0b 11 00 28 f7 0d 11 08 0f 11 00 08 11 09 00 71 00 ?? ?? 00 00 0c 12 1f 12 ?? ?? 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 08 12 0a 00 13 13 00 00 02 00 13 00 23 00 ?? ?? 08 13 00 00 74 03 ?? ?? 11 00 0c 11 08 11 07 00 77 01 ?? ?? 11 00 08 11 0f 00 27 11 0d 11 08 10 11 00 28 f5 }
$S_22_07198 = { 07 c0 01 d1 71 00 ?? ?? 00 00 0c 05 1f 05 ?? ?? 71 10 ?? ?? 05 00 0c 05 07 52 07 25 6e 10 ?? ?? 05 00 0c 05 07 53 07 25 71 00 ?? ?? 00 00 0c 06 1f 06 ?? ?? 12 17 23 77 ?? ?? 07 7b 07 b7 07 b8 12 09 71 00 ?? ?? 00 00 0c 0a 1f 0a ?? ?? 71 10 ?? ?? 0a 00 0c 0a 4d 0a 08 09 6e 30 ?? ?? 65 07 0c 05 07 54 01 15 d8 01 01 ff 3d 05 16 00 07 45 07 36 12 17 23 77 ?? ?? 07 7b 07 b7 07 b8 12 09 71 00 ?? ?? 00 00 0c 0a 4d 0a 08 09 6e 30 ?? ?? 65 07 0c 05 28 e8 07 25 71 00 ?? ?? 00 00 0c 06 1f 06 ?? ?? 12 07 23 77 ?? ?? 6e 30 ?? ?? 65 07 0c 05 07 36 12 07 23 77 ?? ?? 6e 30 ?? ?? 65 07 0c 05 07 50 11 00 }
$S_16_0726 = { 07 20 07 01 54 11 ?? ?? 38 01 08 00 07 01 54 11 ?? ?? 6e 10 ?? ?? 01 00 0e 00 }
$S_6_22598 = { 22 01 ?? ?? 07 15 07 51 07 52 1a 03 ?? ?? 71 10 ?? ?? 03 00 0c 03 70 20 ?? ?? 32 00 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 12 01 01 10 01 01 62 02 ?? ?? 21 22 35 21 17 00 62 01 ?? ?? 01 02 62 03 ?? ?? 01 04 48 03 03 04 62 04 ?? ?? 6e 10 ?? ?? 04 00 0a 04 b7 43 8d 33 4f 03 01 02 d8 00 00 01 28 e6 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 1a 01 ?? ?? 71 10 ?? ?? 01 00 0c 01 69 01 ?? ?? 22 01 ?? ?? 07 15 07 51 07 52 70 10 ?? ?? 02 00 69 01 ?? ?? 12 01 69 01 ?? ?? 0e 00 }
$S_12_0742 = { 07 60 07 71 07 82 07 93 07 04 70 10 ?? ?? 04 00 07 04 07 15 5b 45 ?? ?? 07 04 07 ?? 5b 45 ?? ?? 07 04 07 ?? 5b 45 ?? ?? 0e 00 }
$S_21_0766 = { 07 a0 07 b1 12 04 07 42 07 04 07 15 71 00 ?? ?? 00 00 0c 06 12 07 71 00 ?? ?? 00 00 0c 08 21 88 71 00 ?? ?? 00 00 0c 09 1f 09 ?? ?? 74 06 ?? ?? 04 00 0c 04 07 42 07 24 07 40 11 00 0d 04 07 43 28 fb }
	condition:
10 of them		
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
rule Xavier2_a: ccm
{
        meta:
        description = "This rule was produced by CreateYaraRule and CommonCode, it detects suspicious communications from Xavier"
        author = "_hugo_gonzalez_ "
        strings :
    $S_149_62_48 = { 62 00 ?? ?? 12 ?? 46 00 00 01 71 10 ?? ?? 00 00 71 00 ?? ?? 00 00 0c 00 38 00 09 00 71 00 ?? ?? 00 00 0c 00 72 30 ?? ?? 30 04 0e 00 0d 00 27 00 }
		$S_51_12_120 = { 12 12 12 01 63 00 ?? ?? 39 00 11 00 21 40 dc 00 00 04 38 00 0c 00 22 00 ?? ?? 70 10 ?? ?? 00 00 27 00 0d 00 27 00 0d 00 27 00 63 00 ?? ?? 39 00 13 00 21 40 db 00 00 04 dc 00 00 02 32 20 0c 00 22 00 ?? ?? 70 10 ?? ?? 00 00 27 00 0d 00 27 00 0d 00 27 00 21 40 db 00 00 04 23 00 ?? ?? 6e 40 ?? ?? 43 10 6e 20 ?? ?? 03 00 44 01 00 01 6e 40 ?? ?? 03 12 0c 00 11 00 }
		$S_51_63_94 = { 63 00 ?? ?? 54 51 ?? ?? 39 00 21 00 6e 10 ?? ?? 01 00 0a 00 39 00 08 00 54 50 ?? ?? 12 11 6e 20 ?? ?? 10 00 54 50 ?? ?? 12 01 12 22 23 22 ?? ?? 12 03 4d 06 02 03 12 13 71 10 ?? ?? 07 00 0c 04 4d 04 02 03 6e 30 ?? ?? 10 02 0e 00 0d 00 27 00 0d 00 27 00 0d 00 6e 10 ?? ?? 00 00 28 f7 }
		$S_51_71_44 = { 71 10 ?? ?? 03 00 0c 00 62 01 ?? ?? 12 ?? 46 01 01 02 6e 20 ?? ?? 10 00 0c 01 6e 10 ?? ?? 00 00 0c 00 6e 20 ?? ?? 10 00 0c 00 11 00 }
		$S_102_63_86 = { 63 00 ?? ?? 54 41 ?? ?? 39 00 1d 00 6e 10 ?? ?? 01 00 0a 00 39 00 08 00 54 40 ?? ?? 12 11 6e 20 ?? ?? 10 00 54 40 ?? ?? 12 01 12 22 23 22 ?? ?? 12 03 4d 05 02 03 12 13 4d 06 02 03 6e 30 ?? ?? 10 02 0e 00 0d 00 27 00 0d 00 27 00 0d 00 6e 10 ?? ?? 00 00 28 f7 }
		$S_49_1a_176 = { 1a 00 ?? ?? 6e 10 ?? ?? 00 00 0c 00 21 01 12 02 12 13 36 31 1e 00 07 03 01 24 01 17 07 01 01 70 49 06 01 02 dc 05 04 07 2b 05 34 00 00 00 13 05 ?? 00 b7 65 8e 55 50 05 01 02 d8 02 04 01 39 00 06 00 07 31 01 24 01 02 28 ec 01 01 07 30 36 21 e4 ff 22 01 ?? ?? 70 20 ?? ?? 01 00 6e 10 ?? ?? 01 00 0c 00 69 00 ?? ?? 0e 00 13 05 ?? 00 28 e2 13 05 ?? 00 28 df 13 05 ?? 00 28 dc 13 05 ?? 00 28 d9 13 05 ?? 00 28 d6 13 05 ?? 00 28 d3 00 00 00 01 06 00 00 00 00 00 21 00 00 00 24 00 00 00 27 00 00 00 2a 00 00 00 2d 00 00 00 30 00 00 00 }
		$S_51_12_110 = { 12 01 63 00 ?? ?? 39 00 12 00 21 80 b1 90 da 00 00 04 37 0a 0c 00 22 00 ?? ?? 70 10 ?? ?? 00 00 27 00 0d 00 27 00 0d 00 27 00 23 a4 ?? ?? 01 13 01 10 01 92 35 a3 1c 00 44 05 08 02 da 06 00 08 d9 06 06 18 b9 65 d5 55 ff 00 8d 55 4f 05 04 03 d8 00 00 01 12 45 33 50 06 00 d8 00 02 01 01 02 01 10 d8 03 03 01 28 e7 0d 00 27 00 11 04 }
		$S_192_13_356 = { 13 00 ?? 00 23 0c ?? ?? 12 03 1a 04 ?? ?? 6e 10 ?? ?? 04 00 0a 02 13 05 ?? 00 12 f0 d8 06 00 01 90 00 06 05 6e 30 ?? ?? 64 00 0c 01 12 f0 01 0e 01 20 07 42 01 34 07 13 01 e1 6e 10 ?? ?? 03 00 0c 03 21 37 12 08 12 19 36 97 1e 00 07 39 01 8a 01 7e 07 37 01 e3 49 0d 07 08 dc 0b 0a 07 2b 0b 6d 00 00 00 13 0b ?? 00 b7 db 8e bb 50 0b 07 08 d8 08 0a 01 39 03 06 00 07 97 01 8a 01 38 28 ec 01 37 07 93 36 87 e4 ff 22 07 ?? ?? 70 20 ?? ?? 37 00 6e 10 ?? ?? 07 00 0c 03 2b 01 5f 00 00 00 d8 01 04 01 4d 03 0c 04 90 03 06 05 35 03 0b 00 6e 20 ?? ?? 32 00 0a 05 07 24 01 02 01 30 01 13 28 ae 1a 02 ?? ?? 6e 10 ?? ?? 02 00 0a 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 ?? ?? ?? ?? ?? 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 01 06 00 00 00 00 00 ?? 00 00 00 ?? 00 00 00 ?? 00 00 00 ?? 00 00 00 ?? 00 00 00 ?? 00 00 00 00 01 01 00 00 00 00 00 ?? 00 00 00 }
		$S_51_12_194 = { 12 05 12 11 63 00 ?? ?? 39 00 11 00 21 b0 dc 00 00 02 32 10 0c 00 22 00 ?? ?? 70 10 ?? ?? 00 00 27 00 0d 00 27 00 0d 00 27 00 01 10 21 b2 35 20 49 00 13 02 20 00 44 04 0b 00 d8 03 00 01 44 03 0b 03 01 36 01 47 01 54 d8 03 02 ff 3d 02 31 00 14 02 47 86 c8 61 91 02 04 02 e0 04 06 04 54 a8 ?? ?? 44 08 08 05 b0 84 b7 64 e2 08 06 05 b7 28 b0 84 54 a8 ?? ?? 44 08 08 01 b0 84 b0 47 e0 04 07 04 54 a8 ?? ?? 12 29 44 08 08 09 b0 84 b7 74 e2 08 07 05 b7 28 b0 84 54 a8 ?? ?? 12 39 44 08 08 09 b0 84 b0 64 01 46 01 24 01 32 28 ce 4b 07 0b 00 d8 02 00 01 4b 06 0b 02 d8 00 00 02 28 b7 0e 00 }
		$S_51_13_132 = { 13 02 18 00 12 00 63 01 ?? ?? 39 01 13 00 21 71 db 01 01 04 b0 91 21 83 37 31 0c 00 22 00 ?? ?? 70 10 ?? ?? 00 00 27 00 0d 00 27 00 0d 00 27 00 4b 00 08 09 01 21 01 03 01 90 21 74 35 43 21 00 44 04 08 00 48 05 07 03 d5 55 ff 00 b8 15 b6 54 4b 04 08 00 39 01 12 00 d8 00 00 01 21 81 35 10 11 00 12 01 4b 01 08 00 01 21 d8 03 03 01 28 e6 0d 00 27 00 0d 00 27 00 d8 01 01 f8 28 f7 0e 00 01 21 28 f4 }
		$S_51_12_78 = { 12 12 12 01 21 50 db 03 00 08 21 50 dc 00 00 08 39 00 1d 00 01 10 b0 30 da 00 00 02 d8 00 00 01 23 00 ?? ?? 21 53 4b 03 00 01 6e 40 ?? ?? 54 20 6e 20 ?? ?? 04 00 21 02 da 02 02 04 6e 40 ?? ?? 04 21 0c 00 11 00 0d 00 27 00 01 20 28 e5 }
		$S_102_54_74 = { 54 40 ?? ?? 6e 10 ?? ?? 00 00 0a 00 39 00 08 00 54 40 ?? ?? 12 11 6e 20 ?? ?? 10 00 54 40 ?? ?? 12 01 12 22 23 22 ?? ?? 12 03 4d 05 02 03 12 13 4d 06 02 03 6e 30 ?? ?? 10 02 0e 00 0d 00 27 00 0d 00 6e 10 ?? ?? 00 00 28 f9 }
		$S_51_12_172 = { 12 45 12 00 70 10 ?? ?? 06 00 23 51 ?? ?? 5b 61 ?? ?? 39 07 0d 00 22 00 ?? ?? 62 01 ?? ?? 12 22 46 01 01 02 70 20 ?? ?? 10 00 27 00 21 71 13 02 10 00 35 21 0f 00 22 00 ?? ?? 62 01 ?? ?? 12 02 46 01 01 02 70 20 ?? ?? 10 00 27 00 0d 00 27 00 01 01 35 50 2c 00 54 62 ?? ?? d8 03 01 01 48 01 07 01 d5 11 ff 00 d8 04 03 01 48 03 07 03 d5 33 ff 00 e0 03 03 08 b6 31 d8 03 04 01 48 04 07 04 d5 44 ff 00 e0 04 04 10 b6 14 d8 01 03 01 48 03 07 03 d5 33 ff 00 e0 03 03 18 b6 43 4b 03 02 00 d8 00 00 01 28 d7 0d 00 27 00 0e 00 }
		$S_51_62_50 = { 62 00 ?? ?? 39 00 12 00 22 00 ?? ?? 62 01 ?? ?? 12 12 46 01 01 02 6e 10 ?? ?? 01 00 0c 01 70 20 ?? ?? 10 00 69 00 ?? ?? 62 00 ?? ?? 11 00 0d 00 27 00 }
		$S_51_63_112 = { 63 01 ?? ?? 39 01 28 00 69 03 ?? ?? 62 00 ?? ?? 39 00 22 00 6e 10 ?? ?? 03 00 0c 00 71 10 ?? ?? 00 00 0c 02 71 10 ?? ?? 02 00 0a 00 39 01 18 00 39 00 12 00 1c 00 ?? ?? 6e 10 ?? ?? 00 00 0c 00 6e 20 ?? ?? 20 00 0c 00 71 10 ?? ?? 00 00 0c 00 69 00 ?? ?? 6f 40 ?? ?? 43 65 0a 00 0f 00 0d 00 27 00 0d 00 27 00 0d 00 6e 10 ?? ?? 00 00 28 f3 }
    condition:
        10 of them
}
rule Want2Badmin_a
{
	meta:
		description = "Apps that want to be admins through intents"
	strings:
		$a = "android.app.extra.DEVICE_ADMIN" nocase
		$b = "ADD_DEVICE_ADMIN" nocase
		$c = "DEVICE_ADMIN_ENABLED"
	condition:
		$a or $b or $c
}
rule SUexec_a
{
	meta:
		description = "Caution someone wants to execute a superuser command"
	strings:
		$a = "\"su\", \"-c\""
		$b ="su -c"
	condition:
		$a or $b		
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
rule koodous_ka: official
{
	meta:
		description = "This rule is checking for SMS sending without creds/authentication"
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.CHANGE_CONFIGURATION/) and
		not androguard.permission(/android.permission.AUTHENTICATE_ACCOUNTS/) and
		not androguard.permission(/android.permission.USE_CREDENTIALS/) and
		not androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		not androguard.permission(/android.permission.BLUETOOTH_ADMIN/)
}
rule koodous_la: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name("com.h.M")  
}
rule Downloader_b {
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
rule Xavier_b: basic
{
	meta:
		description = "This rule detects the Xavier malicious ad library"
		sample = "6013393b128a4c6349b48f1d64c55aa14477e28cc747b57a818e3152915b14cc/analysis"
		reference = "http://thehackernews.com/2017/06/android-google-play-app-malware.html"
	condition:
		androguard.activity("xavier.lib.XavierActivity") and
		androguard.service("xavier.lib.message.XavierMessageService")
}
rule sensual_woman_c: chinese
{
	condition:
		androguard.package_name(/com.phone.gzlok.live/)
		or androguard.package_name(/com.yongrun.app.sxmn/)
		or androguard.package_name(/com.wnm.zycs/)
		or androguard.package_name(/com.charile.chen/i)
		or androguard.package_name(/com.sp.meise/i)
		or androguard.package_name(/com.legame.wfxk.wjyg/)
}
rule SMSSend_d
{
	strings:
		$a = "bd092gcj"
		$b = "6165b74d-2839-4dcd-879c-5e0204547d71"
		$c = "SELECT b.geofence_id"
		$d = "_ZN4UtilD0Ev"
	condition:
		all of them
}
rule SMSSend2_d
{
	strings:
		$a = "SHA1-Digest: zjwp/bYwUC5kfWetYlFwr/EuHac="
		$b = "style_16_4B4B4B"
		$c = "style_15_000000_BOLD"
	condition:
		all of them
}
rule koodous_ma: DroidJack
{
	meta:
		author = "dma"
		sample = "81c8ddf164417a04ce4b860d1b9d1410a408479ea1ebed481b38ca996123fb33"
	condition:
		androguard.activity(/net\.droidjack\.server\./i)
}
rule Dvmap_a
{
	strings:
		$a = "com.colourblock.flood"
	condition:
		$a and not androguard.certificate.sha1("D75A495C4D7897534CC9910A034820ABD87D7F2F") 
}
rule Durak_a: MobiDash
{
	meta:
		description = "This rule detects cardgame durak, MobiDash malware"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "mobi.dash.extras.Action_Bootstraped"
	condition:
		androguard.package_name("com.cardgame.durak") and
		androguard.app_name("durak") and
		androguard.filter(/SCREEN_OFF/) and
		androguard.filter(/USER_PRESENT/) and
		androguard.certificate.sha1("b41d8296242c6395eee9e5aa7b2c626a208a7acce979bc37f6cb7ec5e777665a") and 
		$a 	
}
rule spywareSMS_a
{
	meta:
		description = "This rule detects spyware send SMS"
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
rule Bad_news_a: badnews
{
	meta:
		description = "This Yara rule detects things familiar to badnews"
	strings:
		$a = "newdomen"
		$b = "seconddomen"
		$c = "status"
		$d = "iconinstall"
	condition:
		androguard.package_name("com.mobidisplay.advertsv1") and
		androguard.app_name("Badnews") and
		androguard.url(/xxxplay.net/ ) and
		(androguard.permission(/android.permission.INTERNET/) and
		$a and
		$c)
		or
		(androguard.permission(/android.permission.INTERNET/) and
		$b and
		$c)
		or
		(androguard.permission(/android.permission.INTERNET/) and
		$d and
		$c)
}
rule privacy_and_adware_detection_a: privacy_and_adware
{
	meta:
		description = "This rule detects adware and/or potential privacy violating elements of the mightyfrog app and/or other element in the fish.rezepte package "
		weight = 6
	strings:
		$a = "internet"
	condition:
		androguard.package_name("com.fish.Rezepte.de") and
		androguard.app_name("mightyfrog") and
		$a and
		(
		(androguard.activity(/LinkActivity/i) and
		androguard.activity(/BannerActivity/i) and
		androguard.activity(/InAppPushActivity/i))
		or 
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/))
		)
}
rule trojan_b {
	meta:
		description = "Yara rule to find trojan apps"
		author = "Luc Schouten & Dylan macquine"
		date = "11-11-2020"
		sample = "23e6b3d76fcaf00f03c2bd0ce05f0f67e2cdba86dab61450f421e501d756e8ac"
	strings:
	  $function1 = "SmsReceiver;->abortBroadcast"
	condition:
		(androguard.permission(/android.permission.READ_SMS/) and androguard.permission(/android.permission.RECEIVE_SMS/) and androguard.permission(/android.permission.WRITE_SMS/) and androguard.permission(/android.permission.SEND_SMS/) and $function1) and (androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) or androguard.permission(/android.permission.READ_PHONE_STATE/) or androguard.permission(/android.permission.GET_TASKS/)) and androguard.app_name(/battery/)
}
rule spyware_a {
	meta:
		description = "This rule detects similar applications like the Save Me spyware application that can make phone calls"
		sample = "Save Me"
		author = "Luc Schouten & Dylan macquine"
		date = "12-11-2020"
	strings:
		$string1 = "sendTextMessage"
	condition:
	(androguard.service(/CHECKUPD/) and androguard.service(/GTSTSR/) and androguard.url("http://xxxxmarketing.com") and androguard.url("http://topemarketing.com/app.html") and $string1)
}
rule koodous_na: official
{
	meta:
		Author = "Rens en Frank"
		description = "Cajino"
		reference = "http://kharon.gforge.inria.fr/dataset/malware_Cajino.html"
	strings:
		$a = "com.baidu.android.pushservice.action.MESSAGE"
		$b = "com.baidu.android.pushservice.action.RECEIVE"
		$c = "com.baidu.android.pushservice.action.notification.CLICK"
	condition:
		all of them
}
rule SimpLockerRansom_a
{
	meta:
		description = "This rule detects Ransomware similar to SimpLocker"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.package_name("org.simplelocker") and
		androguard.package_name("org.torproject")
}
rule EwindTrojan_a
{
	meta:
		description = "This rule detects an Ewind Trojan"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "http://vignette2.wikia.nocookie.net/logopedia/images/d/d2/Google_icon_2015.png"
		$b = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"
	condition:
		($a or $b) and
		androguard.package_name("com.gus.pizzapaxbielefeld") and
		androguard.permission(/android.permission.GET_TASKS/)
}
rule Antivirus_a
{
	strings:
		$a = "http://"
		$b = "http://checkip.amazonaws.com/"
		$c = "http://example.com"
		$d = "http://play.google.com/store/apps/%s?%s"
		$e = "http://vignette2.wikia.nocookie.net/logopedia/images/d/d2/Google_icon_2015.png"
		$f = "http://www.whoishostingthis.com/tools/user-agent/"
		$g = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"
		$h = "https://play.google.com/store/apps/details?id=org.mightyfrog.android."
	condition:
		androguard.package_name("demo.restaurent.ingeniumbd.demorestaurant") or
		androguard.app_name("AVG AntiVirus 2020 for Android Security FREE") or
		androguard.permission(/android.permission.WRITE_EXTERNAL-STORAGE/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		$a and $b and $c and $d and $e and $f and $g and $h
}
rule koodous_oa: official
{
	meta:
		description = "This is a rule to identify TopSecretVideo and similar malicious apks."
		sample = "f87926a286ecc487469c7b306e25818995fecd3be704a2381d676b9725c647b4"
	strings:
		$a = "http://schemas.android.com/apk/res/android"
	condition:
		androguard.package_name("org.pairjesterutterly") and
		androguard.app_name("TopSecretVideo") and
		androguard.activity(/org.pairjesterutterly.MainActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.certificate.sha1("6a96e534d7aae84b989859ac9c20c5adb5da2507") and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/)
}
rule find_SimpLocker_a
{
	meta:
		authors = "Igor and Elize"
		date = "13 November"
		description = "This is a YARA rule to find SimpLocker"
	strings: 
		$a = "org/simplocker/MainService.java"
		$b = "org/simplocker/MainService$4.java"
		$c = "org/simplocker/TorSender.java"
		$d = "org/simplocker/HttpSender.java"
		$e = "org/simplocker/FilesEncryptor.java"
		$f = "org/simplocker/AesCrypt.java"
		$g = "org/simplocker/Constants.java"
	condition:
		($a and $b and $c and $d and $e and $f and $g)
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

rule Android_Malware_b: iBanking
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
rule feckeny_a
{
	meta:
		description = "This ruleset looks for feckeny's apps"
	condition:
		androguard.certificate.issuer(/feckeny/) 
		or androguard.certificate.subject(/feckeny/)
}
rule InfoStealer_a
{
	condition:
		androguard.package_name(/com.samples.servicelaunch/) and
		androguard.app_name(/ss/)
}
rule Android_Malware_c: iBanking
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
rule dropper_e:realshell {
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$a = "hexKey:"
		$b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
	condition:
		any of them
}
rule silent_banker_i: banker
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
rule silent_banker_j: banker
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
rule silent_banker_k: banker
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
rule silent_banker_l: banker
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
rule silent_banker_m: banker
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
rule silent_banker_n: banker
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
rule Bot_a
{
	strings:
		$a = "/dodownload" ascii wide
		$b = "/dodelete" ascii wide
		$c = "/doupload" ascii wide
		$d = "/doprogress" ascii wide
	condition:
		all of them
}
rule Bot2_a
{
	strings:
		$a = "/download" ascii wide
		$b = "/delete" ascii wide
		$c = "/upload" ascii wide
	condition:
		all of them
}
rule adw_a
{
	meta:
		description = "adware"
	strings:
		$b = "http://a1.adchitu.com/ct"
		$c = "http://a1.zhaitu.info/zt/"
	condition:
		$b and $c
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
rule virus_de_la_policia_a
{
	meta:
		description = "Virus de la policia"
	strings:
		$a = "ScheduleLockReceiver"
		$b = "AlarmManager"
		$c = "com.android.LockActivity"
	condition:
		all of them
}
rule RootApp_a
{
	meta:
		description = "Root app"
	strings:
		$a = "ROOT_ERROR_FAILED"
		$b = "STEP_EXECUTE"
	condition:
		all of them
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
rule rusSMSfraud_a
{
	meta:
		description = "russian porn fraud. tricks the user into a cordova app"
	strings:
		$a = "file:///android_asset/html/end.html"
		$b = "file:///android_asset/html/index.html"
		$c = "sendSms2(): "
	condition:
		all of them
}
rule sending2smtp_a
{
	meta:
		description = "Connects with remote chinese servers"
	strings:
		$a = "18201570457@163.com"
		$b = "smtp.163.com"
	condition:
		$a and $b
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
rule subscript_a
{
	meta:
		description = "Coonecting to one of those sites (Splitting ',') and getting the user into a subscription."
	strings:
		$a = "fapecalijobutaka.biz,ymokymakyfe.biz,kugoheba.biz"
	condition:
		$a 
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
rule locker_c
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
rule Code_Execution_a: official
{
	meta:
		description = "Ejecucion de codigo"
	strings:
		$a = "java/lang/Runtime"
		$b = "exec"
	condition:
		$a and $b
}
rule Umeng_a
{
	meta:
		description = "Evidences of Umeng advertisement library / Adware "
	condition:
		cuckoo.network.dns_lookup(/alog.umeng.com/) or cuckoo.network.dns_lookup(/oc.umeng.com/)
}
rule taskhijack_a: official
{
	meta:
		date = "2015-09-21"
		description = "Posible task Hijack"
		reference = "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf"
	strings:
		$a = /taskAffinity\s*=/
		$b = /allowTaskReparenting\s*=/
		$file = "AndroidManifest.xml"
	condition:
		$file and ($a or $b)
}
rule basebridge_b
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
rule potential_malware_a
{
	meta:
		description = "Potential malware"
	strings:
		$a = "com.example.smsmessaging.TestService"
		$b = "setComponentEnabledSetting"
	condition:
		androguard.permission(/BOOT_COMPLETED/) and
		androguard.permission(/CHANGE_COMPONENT_ENABLED_STATE/) and
		$a and $b
}

rule RootApp_b
{
	meta:
		description = "Root app"
	strings:
		$a = "ROOT_ERROR_FAILED"
		$b = "STEP_EXECUTE"
	condition:
		all of them
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
rule packers_m
{
	meta:
		description = "packers"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_b = "StubApplication"
		$strings_c = "libjiagu"
	condition:
		$strings_b or $strings_c
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
rule adware_f
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
rule Lockerpin2_a: ransomware
{
	meta:
		description = "Lockerpin"
		sample = "ca6ec46ee9435a4745fd3a03267f051dc64540dd348f127bb33e9675dadd3d52"
	strings:
		$alert_text = "All your contacts <b>are copied</b>. If you do not pay the fine, we will <b>notify</b> your <u>relatives</u> and <u>colleagues</u> about <b>the investigation</b>"
	condition:
		(androguard.permission(/android\.permission\.READ_CONTACTST/) or
		androguard.permission(/android\.permission\.DISABLE_KEYGUARD/) or
		androguard.permission(/android\.permission\.WRITE_SETTINGS/)) and
		$alert_text	
}
rule lockerpin_b
{
	meta:
		author = "asanchez"
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
rule FakeGooglePlay_a
{
	meta:
		description = "Fake Google Play applications"
	condition:
		androguard.app_name(/google play/i) and
		not androguard.certificate.sha1("38918A453D07199354F8B19AF05EC6562CED5788")
}
rule FakeWhatsApp_a
{
	meta:
		description = "Fake WhatsApp applications"
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}
rule ransomware_e: svpeng
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
rule locker_a_a
{
	meta:
		description = "Locker.A"
	strings:
		$a = "qqmagic"
	condition:
		$a
}
rule simplelocker_a_a
{
	meta:
		description = "SimpleLocker.A"
	strings:
		$a = "fbi_btn_default"
	condition:
		$a
}
rule gaga01_a:SMSSender
{
	condition:
		cuckoo.network.dns_lookup(/gaga01\.net/)
}
rule Ransomware_b: banker
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
rule shiny_adware_a
{
	condition:
		androguard.package_name(/com.shiny*/) and cuckoo.network.http_request(/http:\/\/fingertise\.com/)
}
rule FakePlayerSMS_a
{
	condition:
		androguard.app_name(/PornoPlayer/) and
		androguard.permission(/SEND_SMS/)		
}
rule koler_domains_b
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
rule koler_builds_b
{
	meta:
		description = "Koler.A builds"
	strings:
		$0 = "buildid"
		$a = "DCEF055EEE3F76CABB27B3BD7233F6E3"
		$b = "C143D55D996634D1B761709372042474"
	condition:
		$0 and ($a or $b)
}
rule koler_class_b
{
	meta:
		description = "Koler.A class"
	strings:
		$0 = "FIND_VALID_DOMAIN"
		$a = "6589y459"
	condition:
		$0 and $a
}
rule koler_D_b
{
	meta:
		description = "Koler.D class"
	strings:
		$0 = "ZActivity"
		$a = "Lcom/android/zics/ZRuntimeInterface"
	condition:
		($0 and $a)
}
rule koler_c_a
{
	meta:
		description = "Koler.C"
	strings:
		$a = "4DD669A2441A11E4B7688DFBE11E6FF3"
		$b = "EB2CF761443C11E496358EF203D3BE74"
	condition:
		$a or $b
}
rule koodous_pa: official
{
	meta:
		description = "This rule detects the dewdewdewdew"
	condition:
		androguard.url(/https:\/\/imgur\.com/UmeUPJG.gif/)
}
rule Android_Dogspectus_rswm_a
{
	meta:
		description = "Yara rule for Dogspectus intial ransomware apk"
		sample = "197588be3e8ba5c779696d864121aff188901720dcda796759906c17473d46fe"
		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"
		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "android.app.action.ADD_DEVICE_ADMIN"
		$str_2 = "Tap ACTIVATE to continue with software update"
	condition:
		(androguard.package_name("net.prospectus") and
		 androguard.app_name("System update")) or
		androguard.certificate.sha1("180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E") or
		(androguard.activity(/Loganberry/i) or 
		androguard.activity("net.prospectus.pu") or 
		androguard.activity("PanickedActivity")) or 
		(androguard.permission(/android.permission.INTERNET/) and
		 androguard.permission(/android.permission.WAKE_LOCK/) and 
		 androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		 all of ($str_*))
}
rule spynote_pkg_a
{
	meta:
		description = "Yara rule for detection of different Spynote based on pkg"
		source = " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "SERVER_IP" nocase
	condition:
		androguard.package_name("dell.scream.application") and 
		$str_1
}
rule andr_sk_bank_a
{
	meta:
		description = "Yara rule for Banking trojan targeting South Korean banks"
		sample = "0af5c4c2f39aba06f6793f26d6caae134564441b2134e0b72536e65a62bcbfad"
		source = "https://www.zscaler.com/blogs/research/android-malware-targeting-south-korean-mobile-users"
		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "NPKI"
		$str_2 = "portraitCallBack("
		$str_3 = "android.app.extra.DEVICE_ADMIN"
		$str_4 = "SMSReceiver&imsi="
		$str_5 = "com.ahnlab.v3mobileplus"
	condition:
		androguard.package_name("com.qbjkyd.rhsxa") or
		androguard.certificate.sha1("543382EDDAFC05B435F13BBE97037BB335C2948B") or
		(androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and 
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and 
		all of ($str_*))
}
rule simplerule_b
{
	meta:
		description = "This rule detects a SMS Fraud malware"
		sample = "4ff3169cd0dc6948143bd41cf3435f95990d74538913d8efd784816f92957b85"
	condition:
		androguard.package_name("com.hsgame.hmjsyxzz") or 
		androguard.certificate.sha1("4ECEF2C529A2473C19211F562D7246CABD7DD21A")
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
rule Moreclasses_a: findingfiles
{
	meta:
		description = "This rule detects if the app contains more than one classes file."
	strings:
		$a = "classes2.dex"
		$b = "classes3.dex"
	condition:
		any of them
}
rule koodous_qa: official
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
rule koodous_ra: official
{
	meta:
		description = "This ruleset detects a family of smsfraud trojans"
		sample = "110f2bd7ff61cd386993c28977c19ac5c0b565baec57272c99c4cad6c4fc7dd4"
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.certificate.sha1("4B01DF162934A8E6CF0651CE4810C83BF715A55D") 
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
rule FakeUpdate_a
{
    condition:
        androguard.certificate.sha1("45167886A1C3A12212F7205B22A5A6AF0C252239")
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
r_aule r_a
{
    strings:
        $re1 = /scripts\/action_request.php$/
    condition:
        $re1
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
rule HummingBad_b: malware
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
rule BadNews_a: official
{
	meta:
		description = "This rule detects BadNews malware, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
	    $a = "AlarmManager"
		$b = "broadcast"
		$c = "primaryServerUrl"
	condition:
		androguard.package_name("com.mobidisplay.advertsv1") and
		androguard.permission(/android.permission.INTERNET/) and
		$a and
		$b and
		$c
}
rule cajino_a
{
	meta:
		description = "This rule is made to identify Cajino or apps that are similar to Cajino"
		author = "LjmK"
		date = "09/11/2020"
	strings:
		$a = "com.baidu.android.pushservice.action.MESSAGE" nocase
		$b = "com.baidu.android.pushservice.action.RECEIVE" nocase
		$c = "com.baidu.android.pushservice.action.notification.CLICK" nocase
		$d = "BaiduUtils" nocase
	condition:
		$a and $b and $c or $d
}
rule CHEAT_a
{
	meta:
		description = "YARA rule assignment 2 Itcs, cheat APK"
		author = "Tessff"
		date = "9/11/2020"
	strings:
		$a = "READ_CONTACTS"
		$b = "SEND_SMS"
		$c = "dropper" nocase
	condition:
		$a and $b and $c 		
}
rule Maliciousapk_a: Maliciousstrings
{
	meta:Authors = "M.Q. Romeijn & M. De Rooij"
		description = "This rule applies to malware from type DroidKungFu. We check for the package name, to check whether a fake google package is present. We focus on a couple of strings that look suspicious or relate to malicious activities. We also look if the exploit -the rage against the cage- is present. This string being present in the code is suspicious."
		sample = "881ee009e90d7d70d2802c3193190d973445d807"
	strings:
		$a = "Legacy"
		$b = "/system/app/com.google.ssearch.apk"
		$c = "imei"
		$d = "/ratc"
		$e = "/system/bin/chmod"
	condition:
		(androguard.package_name("com.allen.mp-1")
		or androguard.package_name("com.google.ssearch"))
		and (
		$a 
		or $b 
		or $c 
		or ($d and $e))
}
rule Potential_Cajino_Variant_a
{
    meta:
        description = "Malware that could potentially belong to Cajino family"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = "ca.ji.no.method2"
        $b = "ca/ji/no/method3/MainActivity.java"
    condition:
        $a or $b 
}
rule koodous_sa: official
{
	meta:
		name = "Lennard Hordijk, Teun de Mast"
		studentnumber = "2716143, 2656566"
		sample = "804a0963b2df68d86b468ea776ef784ab9223135659673a0991c30114ef522e2"
	strings:
		$a = "http://s.appjiagu.com:80/pkl16.html"
	condition:
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.CAMERA/) and
		androguard.permission(/android.permission.RECORD_AUDIO/) and 
		$a 
}
rule DroidKungFu_a
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "881ee009e90d7d70d2802c3193190d973445d807"
	strings:
		$trigger = "adb pull /data/data/com.allen.mp/shared_prefs/sstimestamp.xml"
		$j1 = "onCreate.java"
		$j2 = "updateInfo.java"
		$j3 = "cpLegacyRes.java"
		$j4 = "decrypt.java"
		$j5 = "doExecuteTask.java"
		$j6 = "deleteApp.java"
	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("DroidKungFu1") and
		$trigger and
		$j1 and
		$j2 and
		$j3 and
		$j4 and
		$j5 and
		$j6 and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/)
}
rule Tojan_a: SMS
{
	meta:
		Authors = "M.Q. Romeijn & M. De Rooij"
		description = "The mentioned permissions in the YARA rule contain sensitive information from the user and should not be accessed by applications like a media player. These permissions together with a package name or application name that suggests a media player is possibly malicious. Adding to this, the mentioned receivers should be out of scope for a media player as well, since writing and receiving SMS messages is not something a media player should do."
		sample = "1d69234d74142dba192b53a7df13e42cd12aa01feb28369d22319b67a3e8c15a"
	strings:
		$a = "http://www.pv.com/pvns/"
	condition:
		(androguard.package_name("18042_Video_Player.apk") 
		or androguard.app_name("HD Video Player"))
		and
		(androguard.receiver(/excite.dolphin.strategy.bot.sms.ComposeSmsActivity/) 
		or androguard.receiver(/excite.dolphin.strategy.bot.sms.MmsReceiver/)) 
		and
		(androguard.permission(/android.permission.RECEIVE_SMS/) 
		or androguard.permission(/android.permission.WRITE_SMS/)
		or androguard.permission(/android.permission.READ_SMS/)
		or androguard.permission(/android.permission.SEND_SMS/)) 
		and 
		$a		
}
rule Potential_BankBot_a
{
    meta:
        description = "Potential BankBot"
        threat_level = 3
        in_the_wild = true
    strings:
        $a = "497563fdeef3ddff16577b56169ca690e4ca3a512d3bcd638f2ea46d97d9d2c0"
        $b = "com.gnbikntrhba"
        $c = "28773537b9dd83b77326aea7c55c134257d2a300b7d00dc65e0551e60c94d07e"
		$d = "217a1edf54d37813c00c2579f5e7040a7421cecd48200b3b646d7cabcc5c2285"
		$e = "7a36d25325d32868974c8ea8e2bf26cd8b862119764972f6f3d934913021f201"
    condition:
        $a or $b or $c or $d or $e
}
rule BadNewsAPK_a
{
    meta:
        Author = "Wessel van Putten and Niels Cluistra"
        email = "s2600889@vuw.leidenuniv.nl"
        description = "A rule to detect the malicious BadNews APK"
    strings:
        $a= "fillPostDate.java" 
        $b= "onStartCommand.java"
        $c= "startUpdater.java"
        $d= "sendRequest.java"
    condition:
        $a and $b and $c and $d
}
rule Batterysaver_a
{
    meta:
        Author = "F.S. Hessels"
        Email = "florishessels@gmail.com"
        Date = "08/11/2020"
        Description = "This is a basic YARA rule "
		Reference = "https://www.virustotal.com/gui/file/41fcb61c88f86092e6b302251cd6d6e12f26a8781f6df559859c2daa394ccecd/details"
        Sample = "f5abe3a486de57ce82dcc89e1a63376a"
    strings:
		$a = "http://ad.flurry.com/getAndroidApp.do"
        $b = "http://ad.flurry.com/getCanvas.do"
        $c = "http://d371dlrbpeyd2.cloudfront.net/upgrade/"
        $d = "http://data.flurry.com/aap.do"
        $e = "http://github.com/droidfu/schema"
        $f = "http://lp.mobsqueeze.com/"
        $g = "http://moba.rsigma.com/Localytics/Upload/%s"
        $h = "http://sigma.sgadtracker.com/Event/Put/"
        $i = "http://www.androiddoctor.com/help"
        $j = "https://bugsense.appspot.com/api/errors"
        $k = "https://chart.googleapis.com/chart?cht=p3&chs=250x300&chd=t:"
        $l = "https://data.flurry.com/aap.do"
        $m = "https://market.android.com/details?id="
        $n = "https://ws.tapjoyads.com/"
        $o = "https://ws.tapjoyads.com/connect?"
        $p = "https://ws.tapjoyads.com/offer_completed?"
        $q = "https://ws.tapjoyads.com/set_publisher_user_id?"
        $r = "https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=8246419"
    condition:
        all of them
}
rule Cajino_c
{
    meta:
        Author = "F.S. Hessels"
        Email = "florishessels@gmail.com"
        Date = "08/11/2020"
        Description = "This is a basic YARA rule "
		Reference = "https://www.virustotal.com/gui/file/41fcb61c88f86092e6b302251cd6d6e12f26a8781f6df559859c2daa394ccecd/details"
        Sample = "f5abe3a486de57ce82dcc89e1a63376a"
    strings:
		$a = "http://ad.flurry.com/getAndroidApp.do"
        $b = "http://ad.flurry.com/getCanvas.do"
        $c = "http://d371dlrbpeyd2.cloudfront.net/upgrade/"
        $d = "http://data.flurry.com/aap.do"
        $e = "http://github.com/droidfu/schema"
        $f = "http://lp.mobsqueeze.com/"
        $g = "http://moba.rsigma.com/Localytics/Upload/%s"
        $h = "http://sigma.sgadtracker.com/Event/Put/"
        $i = "http://www.androiddoctor.com/help"
        $j = "https://bugsense.appspot.com/api/errors"
        $k = "https://chart.googleapis.com/chart?cht=p3&chs=250x300&chd=t:"
        $l = "https://data.flurry.com/aap.do"
        $m = "https://market.android.com/details?id="
        $n = "https://ws.tapjoyads.com/"
        $o = "https://ws.tapjoyads.com/connect?"
        $p = "https://ws.tapjoyads.com/offer_completed?"
        $q = "https://ws.tapjoyads.com/set_publisher_user_id?"
        $r = "https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=8246419"
    condition:
        $a and $b and $c or all of them
}
rule Cajino_d
{
    meta:
        Author = "R.R.J. Schreuder"
        Email = "rickie.schreuder@gmail.com"
        Reference = "http://kharon.gforge.inria.fr/dataset/malware_Cajino.html"
        Date = "05/11/2020"
        Description = "This is a basic YARA rule for a CEO fraud with Caijno"
        Sample = "B3814CA9E42681B32DAFE4A52E5BDA7A"
    strings:
        $a = "method3/MainActivity.java"
        $b = "method3/BaiduUtils.java"
        $c = "getIt.java"
        $d = "getLocation.java"
        $e = "method2/BaiduUtils.java"
    condition:
        $a and $b and $c or all of them
}
rule adware_g
{
	meta:
		description = "Used to identify apps using suspicious URLs (associated with adware)"
	condition:
		androguard.url("1downloadss0ftware.xyz") or cuckoo.network.dns_lookup(/1downloadss0ftware\.xyz/)
		or androguard.url("checkandgo.info") or cuckoo.network.dns_lookup(/checkandgo\.info/)
}
rule SimpLocker_b
{
	meta:
		description = "This rule aims to detect SimpLocker and other related ransomware"
	strings:
		$a = "simplelocker"
	condition:
		$a or
		androguard.app_name("Sex xionix") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
}
rule basic_spyware_a
{
	meta:
		description = "This very basic rule aims to detect spyware"
	strings: 
		$a = "http://ec2-54-197-38-201.compute-1.amazonaws.com:22222?model="
	condition:
		$a or
		androguard.package_name("com.system.servicess") and
		androguard.app_name("Google Services") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.CAMERA/) and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/)
}
rule Cajino_e
{
	meta:
		description = "This rule detects Cajino spyware."
	strings:
		$location = ".getLastKnownLocation()"
		$deviceID = ".getDeviceId()"
		$record = "recorder.start()"
		$sms = "sendTextMessage"
	condition:
		$location and
		$deviceID and
		$record and
		$sms
}
rule antiWipeLocker_a
{
	meta:
		description = "Rule against the antiWipeLocker malware"
	strings:
		$preDeletion = "wipeMemoryCard" nocase
		$hideApp = "HideAppFromLauncher" nocase
		$doubleCheck0 = "setComponentEnabledSetting(this.getComponentName(), 2, 1);"
		$doubleCheck1 = "setComponentEnabledSetting(this.getComponentName(), 2, DONT_KILL_APP);"
		$doubleCheck2 = "setComponentEnabledSetting(this.getComponentName(), COMPONENT_ENABLED_STATE_DISABLED, 1);"
		$doubleCheck3 = "setComponentEnabledSetting(this.getComponentName(), COMPONENT_ENABLED_STATE_DISABLED, DONT_KILL_APP);"
	condition:
		$preDeletion or ($hideApp and ($doubleCheck0 or $doubleCheck1 or $doubleCheck2 or $doubleCheck3))
}
rule Cajino_f: official
{
	meta:
		Author = "Teun de Mast"
		Studentnumber = "2656566"
		Description = "A rule to detect Cajino (remote controlled spyware)"
		Reference = "http://kharon.gforge.inria.fr/dataset/malware_Cajino.html"
	strings:
		$a = "com.baidu.android.pushservice.action.MESSAGE"
		$b = "com.baidu.android.pushservice.action.RECEIVE"
		$c = "com.baidu.android.pushservice.action.notification.CLICK"
		$d = "업데이트"
		$e = "새버전으로 업데이트 합니다 "
		$f = "application/vnd.android.package-archive"
	condition:
		$a and $b and $c and $d and $e and $f
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
rule koodous_ta: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}
	condition:
 crashlytics to debug our app!
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
rule RootedCheck_a
{
	meta:
		description = "This rule detects applications checking for/or requiring root access."
	strings:
		$a = "bin/which su"
		$b = "/sbin/su"
		$c = "system/bin/su"
		$d = "bin/which su"
		$e = "Superuser.apk"
		$f = "/system/xbin/su"
		$g = "/data/local/xbin/su"
		$h = "/data/local/bin/su"
		$i = "/system/sd/xbin/su"
		$j = "/system/bin/failsafe/su"
		$k = "/data/local/su"
		$l = "/system/xbin/which"
		$m = "which su"
	condition:
		$a or
		$b or
		$c or
		$d or
		$e or
		$f or
		$g or
		$h or
		$i or
		$j or
		$k or
		$l or $m
}
rule cordova_a
{
	meta:
		description = "This rule detects Cordova Apps"
	strings:
		$a = "org.apache.cordova"
		$b = "com.adobe.phonegap"
	condition:
		$a or $b
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
rule bazdidyabScamCampaign_a
{
	meta:
		description = "A sample from Scam and Mass Advertisement campaign spreading their scamware over telegram, making money by scamming users and adding them to mass advertisement channels in Telegram"
		sample = "c3b550f707071664333ac498d1f00d754c29a8216c9593c2f51a8180602a5fab"
	condition:
		androguard.url(/^https?:\/\/([\w\d]+\.)?bazdidyabtelgram\.com\/?.*$/)
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
rule koodous_ua: official
{
	meta:
		description = "pegasus"
	strings:
		$a = "coldboot_init"
		$b = "/csk"
	condition:
		$a and $b
}
rule chrysaor_pegasus_a {
	meta:
		sample = "ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5"
		description = "https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-android-technical-analysis.pdf"
		author = "A.Sanchez <asanchez@koodous.com>"
	strings:
		$md5_pad = {B6 27 DB 21 5C 7D 35 E4}
		$file_1 = "/upgrade/uglmt.dat"
		$file_2 = "/upgrade/cuvmnr.dat"
		$file_3 = "/upgrade/zero.mp3"
		$d = "pm uninstall com.sec.android.fotaclient"
	condition:
		all of them
}
rule chrysaor_pegasus2_a {
	meta:
		sample = "3474625e63d0893fc8f83034e835472d95195254e1e4bdf99153b7c74eb44d86"
		description = "https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-android-technical-analysis.pdf"
		author = "A.Sanchez <asanchez@koodous.com>"
	strings:
		$file_1 = "/mnt/obb/.coldboot_init"
		$library = "libsgn.so"
		$url = "/adinfo?gi=%s&bf=%s"
		$function_1 = "random_hexlified_md5" 
		$function_2 = "get_mac_address"
	condition:
		all of them
}
rule Ransomware_c
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
rule ransomware_f
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
rule FakeCMSecurity_a: Certs
{
    condition:
        androguard.certificate.sha1("2E66ED3E9EE51D09A8EFCE00D32AE5E078F1F1B6")
}
rule AirPush_b
{
	meta:
        description = "Evidences of AirPush Adware SDK."
	strings:
		$1 = "api.airpush.com/dialogad/adclick.php"
		$2 = "Airpush Ads require Android 2.3"
   	condition:
    	1 of them
}
rule Developers_with_known_malicious_apps_b
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
rule Banker_e
{
	condition:
		androguard.certificate.issuer(/@attentiontrust\.[a-z]{2,3}/) and
		androguard.certificate.issuer(/Attention Trust/)
}
rule Trojan_h: BankBot
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
rule Trojan_2_c: BankBot
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
rule Trojan_3_c: BankBot
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
rule Trojan_4_c: BankBot
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
rule marcher_a
{
	meta:
		description = "This rule detects Sicherheits-App Banker Trojans, also known as Marcher"
		sample = "8994b4e76ced51d34ce66f60a9a0f5bec81abbcd0e795cb05483e8ae401c6cf7"
	condition:
		androguard.package_name(/[a-z]+\.[a-z]+/) and
		androguard.app_name(/.*Sicherheits[- ]App$/) and
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")
}
rule AirPaySDKActivity_a
{
	meta:
		description = "All AirPay SDK Apps"
	condition:
		androguard.activity("com.airpay.airpaysdk_simplifiedotp.AirpayActivity")
}
rule PayNimoActivity_a
{
	meta:
		description = "All PayNimo SDK Apps"
	condition:
		androguard.activity("com.paynimo.android.payment.PaymentActivity")
}
rule mobstspy_a
{
	meta:
		description = "#MOBSTSPY"
		sample = "32b5d73c3f88d07abb0527f44136dedf13c8d728d9ec37321b40246ffb272aa8"
	strings:
		$a = "moc.ppatratsibom.www//:ptth"
	condition:
		$a
}
rule ZaakPayTracker_a
{
	meta:
		description = "This rule detects ZaakPay gateway powered apps"
	strings:
		$a = "https://api.zaakpay.com/zaakpay.js"
		$b = "https://api.zaakpay.com/"
	condition:
		($a or $b) and
		androguard.permission(/android.permission.INTERNET/)		
}
rule MasterPassQRActivityTracker_a
{
	meta:
		description = "All Masterpass QR Scan Apps"
	condition:
		androguard.activity("com.masterpassqrscan.MasterPassQrCodeCaptureActivity")
}
rule FingPayActivity_a
{
	meta:
		description = "All FingPay SDK Apps"
	strings:
		$a = "https://fingpayap.tapits.in/fpaepsservice/"
	condition:
		($a) or
		androguard.activity("com.tapits.fingpay.FingerPrintScreen")
}
rule KhoslaSDKTrackerActivity_a
{
        meta:
                description = "All Khosla SDK Apps"
        condition:
                androguard.activity("com.khoslalabs.aadhaarbridge.AadhaarBridge")
}
rule AxisMerchantSDKActivity_a
{
	meta:
		description = "All Axis Merchant SDK Apps"
	condition:
		androguard.activity("com.axis.axismerchantsdk.activity.PayActivity")
}
rule aadhaar_vid_generators_a
{
	meta:
		description = "This rule detects Aadhaar VID Generation in apps"
	strings:
		$a = "https://resident.uidai.gov.in/web/resident/vidgeneration"
		$b = "https://resident.uidai.gov.in/vidgeneration"		
	condition:
		($a or $b) and
		androguard.permission(/android.permission.INTERNET/)		
}
rule JDPaySDKTrackerActivity_a
{
	meta:
		description = "All JDPay SDK Apps"
	condition:
		androguard.activity("com.justdialpayui.PaymentsActivity")
}
rule BenowSDKTrackerActivity_a
{
	meta:
		description = "All Benow SDK Apps"
	condition:
		androguard.activity("com.benow.paymentsdk.activities.WebViewActivity")
}
rule NSDLESignSDKTrackerActivity_a
{
	meta:
		description = "All NSDL eSign SDK Apps"
	condition:
		androguard.activity("com.nsdl.egov.esignaar.NsdlEsignActivity")
}
rule SignDeskESignSDKTrackerActivity_a
{
	meta:
		description = "All SignDesk eSign SDK Apps"
	condition:
		androguard.activity("in.signdesk.esignsdk.esign.eSign")
}
rule Flutter_a
{
	meta:
		description = "Detect APK using flutter runtime"
		sample = "8fce0488c977c88710a9a769956543ccd900682bbb8989a23a193bfc2a8f0a92"
	strings:
		$a = "environmentChecksXamarin"
		$b = "doProbe"
		$c = "positiveRootCheck"
	condition:
		any of them
}
rule Flutter_b
{
	meta:
		description = "Detect APK using flutter runtime"
		sample = "8fce0488c977c88710a9a769956543ccd900682bbb8989a23a193bfc2a8f0a92"
	strings:
		$a = "libflutter.so"
	condition:
		any of them
}
rule Gen_AIDE_a
{
	meta:
		description = "Rule to detect malware variant (ex:Jisut)"
		ref = "https://www.welivesecurity.com/wp-content/uploads/2016/02/Rise_of_Android_Ransomware.pdf"
		condition:
		 androguard.service("cn.sadsxcds.sadcccc.SmSserver") or
		 androguard.activity("com.dq.raw.MainActivity") or
		 androguard.activity("com.magic.ten.mad.MainActivity") or
         androguard.receiver("com.h.MyAdmin") or
		 androguard.receiver("com.h.bbb") or
		 androguard.receiver("com.sssp.bbb") or
		 androguard.receiver("com.sssp.MyAdmin") or
		 androguard.receiver("com.cjk.bbb") or
		 androguard.receiver("com.cjk.MyAdmin") or
		 androguard.receiver("com.cute.pin.Pin") or
		 androguard.receiver("com.sunglab.bigbanghd.Service")
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
rule Banker_f: Cosmetiq Targeting German Banks
{
	meta:
        description = "Banker 'Cosmetiq' targeting German Banks"
	strings:
		$c2_prefix = "{\"to\":"
		$c2_mid = "\",\"body\":"
		$c2_suffix = "php\"},"
		$target1 = "com.starfinanz.smob.android.sfinanzstatus" nocase
		$target2 = "com.starfinanz.smob.android.sbanking" nocase
		$target3 = "de.fiducia.smartphone.android.banking.vr" nocase
		$target4 = "de.dkb.portalapp" nocase
		$target5 = "de.postbank.finanzassistent" nocase
		$target6 = "com.starfinanz.mobile.android.dkbpushtan" nocase
		$com1 = "upload_sms"
		$com2 = "send_sms"
		$com3 = "default_sms"
		$com4 = "sms_hook"
		$com5 = "gp_dialog_password"
		$com6 = "gp_password_visa"
		$com7 = "gp_password_master"
	condition:
		all of ($c2*)
		and 1 of ($target*) 
		and 2 of ($com*) 
		and androguard.permission(/android.permission.RECEIVE_SMS/)
}
rule Slempo_b: targeting installed Apps
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
rule Marcher_c: Targeting German Banks
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
rule Dropper_a: OmniRAT Dropper
{
	meta:
        description = "Dropper for OmniRAT"
	condition:
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) 
		and androguard.activity(/net.filsh.youtubeconverter.MainActivity/)
}
rule PUA_b: Ozzie
{
	condition:
		androguard.certificate.sha1("c24d1b4c81226bad788c0d266bba520ec0d8c2f7") 
}
rule safe_a: Alitalia
{
	condition:
		androguard.certificate.sha1("e58eacbcb251314d8afcb5a267dd247c9311afd2") 
}
rule MonTransitApps_a: safe
{
	condition:
		androguard.certificate.sha1("ee6bb0756a02113fd46f2c434a06ebd5d04ff639")
}
rule safe_b: PayU
{
	condition:
		androguard.certificate.sha1("bbb54a9135199f225e8a10e571d264a0e51601ef") 
}
rule Safe_a: Creativeglance
{
	condition:
		androguard.certificate.sha1("2f0bd554308b8193c3486aec1d3841c70b13c866")
}
rule PUA_c: ASDD
{
	condition:
		androguard.certificate.sha1("ed9a1ce1f18a1097dccc5c0cb005e3861da9c34a") 
}
rule koodous_va: UC_Safe
{
	condition:
		androguard.package_name("com.uc.iflow") and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139")  
}
private global rule samsung_Safe
{
	condition:
		androguard.certificate.sha1("9ca5170f381919dfe0446fcdab18b19a143b3163")
}
rule Android_Switcher_a
{
	meta:
		description = "This rule detects Android wifi Switcher variants"
		sample = "d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150"
		source = "https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/"
	strings:
		$str_1 = "javascript:scrollTo"		
		$str_5 = "javascript:document.getElementById('dns1')"
		$str_6 = "admin:"
		$dns_2 = "101.200.147.153"
		$dns_3 = "112.33.13.11"
		$dns_4 = "120.76.249.59"
	condition:
		androguard.certificate.sha1("2421686AE7D976D19AB72DA1BDE273C537D2D4F9") or 
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and 
		($dns_2 or $dns_3 or $dns_4) and all of ($str_*))
}
rule koodous_wa: official
{
	meta:
		description = "Triada token(https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/)"
		sample = "0cc9bcf8ae60a65f913ace40fd83648e"
	strings:
		$a = {63 6f 6e 66 69 67 6f 70 62}
	condition:
		$a
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
rule koodous_xa: official
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
rule Android_pinkLocker_a
{
	meta:
		description = "Yara detection for Android Locker app named Pink Club"
		sample = "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d"
		author = "https://twitter.com/5h1vang"
	strings:
		$str_1 = "arnrsiec sisani"
		$str_2 = "rhguecisoijng ts"
		$str_3 = "assets/data.db"
		$str_4 = "res/xml/device_admin_sample.xmlPK" 
	condition:
		androguard.url(/lineout\.pw/) or 
		androguard.certificate.sha1("D88B53449F6CAC93E65CA5E224A5EAD3E990921E") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		all of ($str_*)
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
rule Android_Dendroid_b
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
rule pokemongo_b: fake
{
	meta:
		description = "This rule detects fakes Pokemon Go apps "
		sample = ""
	condition:
		(androguard.package_name("com.nianticlabs.pokemongo") or androguard.app_name("Pokemon GO")) and not
		androguard.certificate.sha1("321187995BC7CDC2B5FC91B11A96E2BAA8602C62")
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
rule tinhvan_a
{
	meta:
		sample = "0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5"
	condition:
		androguard.certificate.sha1("0DFBBDB7735517748C3DEF3B6DEC2A800182D1D5")
}
rule AoHaHa_a: SMSSender
{
	condition:
		androguard.certificate.sha1("79A25BCBF6FC9A452292105F0B72207C3381F288")
}
rule fake_installer_a: orggoogleapp
{
	condition:
		androguard.certificate.sha1("86718264E68A7A7C0F3FB6ECCB58BEC546B33E22")				
}
rule BaDoink_a: official
{
	meta:
		description = "Virus de la Policia - android"
		sample = "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"
	strings:
		$type_a_1 ="6589y459gj4058rt"
		$type_b_1 = "Q,hu4P#hT;U!XO7T,uD"
		$type_b_2 = "+Gkwg#M!lf>Laq&+J{lg"
	condition:
		androguard.app_name("BaDoink") or
		$type_a_1 or
		all of ($type_b*) 
}
rule AirPush_c: AirPush
{
	meta:
		description = "This rule detects AirPush"
	strings:
		$type_a_1 = "ZeIdg9Q9b"
		$type_a_2 = "lib/armeabi/libcrypt.so"
		$type_b_1 = "res/menu/install_games.xml"
		$type_b_2 = "resources.zip"
		$type_b_3 = "XCIFLNLKNFVVKHFFW"
	condition:
		all of ($type_a_*) and androguard.activity(/com.intrinsic.*/) or
		all of ($type_b_*) and androguard.activity(/com.yzurhfxi.*/)
}

rule koodous_ya: official
{
	meta:
		description = "Rubobi"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "surprise"
		$b = "r/6UyV_i"
	condition:
		$a and $b and androguard.permission(/android.permission.SEND_SMS/)
}
rule chineseSMSSender_a
{
	condition:
		androguard.package_name("com.android.phonemanager") and
		androguard.permission(/android.permission.SEND_SMS/)
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
rule adware_h: ads
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
rule dropper_f:realshell {
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
	condition:
		$b
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
rule test_d: adware
{
    condition:
		androguard.app_name(/{d0 a3 d1 81 d1 82 d0 b0 d0 bd d0 be d0 b2 d0 ba d0 b0}/) or androguard.package_name(/com\.tujtr\.rtbrr/)
}
rule fake_market_b
{
	condition:
		androguard.package_name("com.minitorrent.kimill") 
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
rule chineseporn4_a: SMSSend
{
	condition:
		androguard.activity(/com\.shenqi\.video\.Welcome/) or
		androguard.package_name("org.mygson.videoa.zw")
}
rule londatiga_a
{
	condition:
		androguard.certificate.sha1("ECE521E38C5E9CBEA53503EAEF1A6DDD204583FA")
}
rule Installer_a: banker
{
	meta:
		description = "Applications with Installer as an application name"
	condition:
		androguard.package_name("Jk7H.PwcD")
}
rule FinSpy_a
{
	meta:
		description = "FinSpy"
		info = "http://maldr0id.blogspot.com.es/2014/10/whatsapp-with-finspy.html"
	strings:
		$a = "4j#e*F9+Ms%|g1~5.3rH!we"
	condition:
		$a
}
rule ransomware_g: svpeng
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
rule chinese_porn_a: SMSSend
{
	condition:
		androguard.package_name("com.tzi.shy") or
		androguard.package_name("com.shenqi.video.nfkw.neim") or
		androguard.package_name("com.tos.plabe")
}
rule minecraft_a
{
	condition:
		( androguard.app_name("Minecraft: Pocket Edition") or 
			androguard.app_name("Minecraft - Pocket Edition") )
		and not androguard.package_name("com.mojang.minecraftpe")
}
rule hostingmy_a
{
	condition:
		androguard.certificate.issuer(/hostingmy0@gmail.com/)
}
rule MetaMaskClipper_a {
	meta:
		description = "Detects association with the clipper used in the MetaMask impersonating trojan"
rulePurpose = "Educational exercise"_a
	strings:
		$ethAddress = "0xfbbb2EF692B5101f16d3632f836461904C761965"
		$btcAddress = "17M66AG2uQ5YZLFEMKGpzbzh4F1EsFWkmA"	
		$methodName = "onPrimaryClipChanged"
		$setterName = "setPrimaryClip"		
	condition:
		$ethAddress or 
		$btcAddress or 
		($methodName and $setterName) or (
			androguard.app_name("MetaMask") and		
			androguard.permission(/ACCESS_NETWORK_STATE/) and
			androguard.permission(/INTERNET/) and
			androguard.permission(/WRITE_EXTERNAL_STORAGE/) and		
			androguard.url(/api\.telegram\.org/)) or
		androguard.certificate.sha1("14F52769440E01A4CEF3991FB081637CD10BDBB3")
}
rule covid19ransom_a
{
	meta:
		description = "This rule detects the Covid19 APK with Ransomware"
		sample = "6b74febe8a8cc8f4189eccc891bdfccebbc57580675af67b1b6f268f52adad9f"
	condition:
		androguard.package_name("com.device.security") or (
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.BIND_DEVICE_ADMIN/) and
		cuckoo.network.http_request(/https:\/\/qmjy6\.bemobtracks\.com\/go\/4286a004-62c6-43fb-a614-d90b58f133e5/)
		)
}
rule SMSTrojan_a
{
	meta:
		description = "Rule to detect SMS trojans in APK files"
		sample = "ff8ccead81eca2154cf9e891e15f52c8a154ea3aba5e62498b11fb843135837f"
		source = "http://pastebin.com/rLPux7ts"
	strings:
		$d = "com.android.install"
	condition:
		all of them
}
rule aliyuncs_a: generic
{
	meta:
		description = "Try to detect Aliyunics related apps."
	strings:
		$url = /\.aliyuncs\.com/ nocase  // Privacy policy links use this
	condition:
		$url
}
rule ijoysoft_a
{
	meta:
		description = "Detect ijoysoft ad library"
	strings:
		$name = /ijoysoft/
		$a1 = "REMOTE IS NULL or PARCEL IS NULL !!!"
		$a2 = /you donot call with\(\) before/
		$a3 = "CREATE TABLE IF NOT EXISTS gift (_id INTEGER PRIMARY KEY AUTOINCREMENT,_index INTEGER DEFAULT 0,package TEXT UNIQUE NOT NULL, title TEXT, details TEXT, icon TEXT, url TEXT, poster TEXT, clicked INTEGER DEFAULT 0, submitted INTEGER DEFAULT 0, r_count INTEGER DEFAULT 0, d_count INTEGER DEFAULT 0, l_count INTEGER DEFAULT 0, version text )"
	condition:
		$name or any of ($a*)
}
rule Trojan_i: BankBot
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
rule ElfEqual_MobileOffers_a
{
	meta:
		description = "A 'MobileOffers' app"
		sample = "7f2dbed572155425fbaae8d2bdfc5bad5e16a2e7a4e3698b486505e9954dc6ab"
		sample = "C1870A8AFF2FB4EEDCAE2C3CB091F75A7046343A8F472F3F6B5AC07D1382925D"
		sample_url = "https://mobileoffers-br-download.com/830/171?file=TeamSpeak%203%20v3.3.2%20Apk%20Paid%20Full"
		sample_url_description = "Must use an Android User-Agent, otherwise you'll be redirected to Google Play."
	strings:
		$ = "x0"
		$ = "x1"
		$ = { 7f 45 4c 46 3d }
	condition:
		all of them	
}
rule Obfuscapk_LibEncryption_a
{
  meta:
    description = "Obfuscapk - LibEncryption plugin"
    url         = "https://github.com/ClaudiuGeorgiu/Obfuscapk"
    author      = "packmad - https://twitter.com/packm4d"
    sample      = "4957d9c1b423ae045f27d97b1d0b1f32ba6a2ce56525a2e93bda7172ec18ad0c"
  strings:
    $lib_arm = /assets\/lib\.arm(eabi|64)-v[0-9a-zA-Z]{2}\.[!-~]+\.so/
    $lib_x86 = /assets\/lib\.x86(_64)?\.[!-~]+\.so/
  condition:
    any of them
}
rule APK_PK336_CL2_1R_a
{
	meta:
		description = "2 classes, 1 generated R class and all those strings... Has payload 100% guaranteed"
		sample = "d941a4f11ecaf9472692d0707d126ee085dbd84af699e21cfab07db16dbbc992"
		sample = "e69c1b28584a9abadb7cd6d07d277de071c354c5f02f973fe99c3eb6c5f01d5b"
	strings:
		$ = "android.app.ActivityThread$ProviderClientRecord"
		$ = "android.app.ActivityThread$AppBindData"
		$ = "android.content.ContentProvider"
		$ = "android.app.ActivityThread"
		$ = "android.app.LoadedApk"
		$ = "mInitialApplication"
		$ = "mLocalProvider"
		$ = "mClassLoader"
		$ = "mProviderMap"
		$ = "mContext"
		$ = "jar"
	condition:
		all of them
}
rule legu_a: packer
{
    meta:
		description = "test rule to identify Legu Packer"
	strings:
		$a = "assets/toversion"
		$b = "assets/0OO00l111l1l"
		$c = "assets/0OO00oo01l1l"
		$d = "assets/o0oooOO0ooOo.dat"
	condition:
		$b and ($a or $c or $d)
}
rule redrabbit_a: ShadowVoice
{
	meta:
		description = "This rule detects the voicephishing app targeted for Korean"
	condition:
		androguard.package_name("com.red.rabbit") and
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALL/)
}
rule redrainbow_a: ShadowVoice
{
	meta:
		description = "This rule detects the voicephishing app targeted for Korean"
	condition:
		androguard.package_name("com.red.rainbow") and
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALL/)
}
rule APT_hmza_a
{
	meta:
		description = "This rule will be able to tag all hmza APT samples"
		hash_1 = "2d0a56a347779ffdc3250deadda50008d6fae9b080c20892714348f8a44fca4b"
		hash_2 = "caf0f58ebe2fa540942edac641d34bbc8983ee924fd6a60f42642574bbcd3987"
		hash_3 = "b15b5a1a120302f32c40c7c7532581ee932859fdfb5f1b3018de679646b8c972"
		hash_4 = "c7f79fcf491ec404a5e8d62d745df2fa2c69d33395b47bc0a1b431862002d834"
		author = "Jacob Soo Lead Re"
		date = "25-December-2018"
	condition:
		(androguard.service(/NetService/i)
		and androguard.receiver(/hmzaSurvival/i) 
		and androguard.receiver(/SystemUpteen/i)) or 
		(androguard.service(/NtSrvice/i)
		and androguard.receiver(/hzaSrvval/i) 
		and androguard.receiver(/SystmUptn/i))
}
rule Chrome_a: fake
{
	condition:
		(
		androguard.app_name(/^Chr[o0]me$/i) or
		androguard.package_name(/com.chrome/) or
		androguard.package_name(/com.android.chrome/)
		) and not (
		androguard.certificate.sha1("38918A453D07199354F8B19AF05EC6562CED5788") or
		androguard.certificate.sha1("D3CC1758A154EB7DD9FFBE5295016733C9682161")
		)
}
rule Discord_a: fake
{
	condition:
		(
		androguard.app_name(/^D[il1]sc[o0]rd$/i) or
		androguard.package_name(/com.discord/)
		) and not (
		androguard.certificate.sha1("B07FC6AECCD21FCBD40543C85112CAFE099BA56F")
		)
}
rule Facebook_a: fake
{
	condition:
		(
		androguard.app_name(/^Faceb[o0][o0]k$/i) or
		androguard.package_name(/com.facebook/)
		) and not (
		androguard.certificate.sha1("8A3C4B262D721ACD49A4BF97D5213199C86FA2B9") or
		androguard.certificate.sha1("7BA7EFE97151AFEB57103266B1200D85A805D7D6")
		)
}
rule Facebook_Lite_a: fake
{
	condition:
		(
		androguard.app_name(/^Faceb[o0][o0]k[ ]?L[il1]te$/i) or
		androguard.app_name(/^L[il1]te$/i) or
		androguard.package_name(/com.facebook.lite/)
		) and not (
		androguard.certificate.sha1("8A3C4B262D721ACD49A4BF97D5213199C86FA2B9")
		)
}
rule Google_Apps_a: fake
{
	condition:
		(
		androguard.package_name(/com.google/) or
		androguard.package_name(/com.android.google/)
		) and not (
		androguard.certificate.sha1("38918A453D07199354F8B19AF05EC6562CED5788") or
		androguard.certificate.sha1("24BB24C05E47E0AEFA68A58A766179D9B613A600") or
		androguard.certificate.sha1("0980A12BE993528C19107BC21AD811478C63CEFC") or
		androguard.certificate.sha1("203997BC46B8792DC9747ABD230569071F9A0439") or
		androguard.certificate.sha1("1F387CB25E0069EFCA490ADE28C060E09D37DD45") or
		androguard.certificate.sha1("9FA50D00B0F4BDAA5D8F371BEA982FB598B7E697") or
		androguard.certificate.sha1("EE3E2B5D95365C5A1CCC2D8DFE48D94EB33B3EBE") or
		androguard.certificate.sha1("26710BDB08F6463B1F5842E2775169E31DD07301")
		)
}
rule Instagram_a: fake
{
	condition:
		(
		androguard.app_name(/^[Il1]nstagram$/i) or
		androguard.package_name(/com.instagram/)
		) and not (
		androguard.certificate.sha1("C56FB7D591BA6704DF047FD98F535372FEA00211")
		)
}
rule Telegram_a: fake
{
	condition:
	(
	androguard.app_name(/^Telegram$/i) or
	androguard.package_name(/org.telegram.messenger/)
	) and not (
	androguard.certificate.sha1("9723E5838612E9C7C08CA2C6573B6026D7A51F8F")
	)
}
rule Twitter_a: fake
{
	condition:
	(
	androguard.app_name(/^Tw[il1]tter$/i) or
	androguard.package_name(/com.twitter/)
	) and not (
	androguard.certificate.sha1("40F3166BB567D3144BCA7DA466BB948B782270EA")
	)
}
rule WhatsApp_b: fake
{
	condition:
		(
		androguard.app_name(/^What[']?s[ ]?App$/i) or
		androguard.package_name(/com.whatsapp/)
		) and not (
		androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
		)
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
rule CopyCat_a: adware
{
	meta:
		description = "Detects domains used by the CopyCat adware"
		source = "https://www.checkpoint.com/downloads/resources/copycat-research-report.pdf"
	strings:
		$a1 = /.mostatus.net/i
		$a2 = /.mobisummer.com/i
		$a3 = /.clickmsummer.com/i
		$a4 = /.hummercenter.com/i
		$a5 = /.tracksummer.com/i
	condition:
		any of them or (
		androguard.url(/.mostatus.net/i) or
		androguard.url(/.mobisummer.com/i) or
		androguard.url(/.clicksummer.com/i) or
		androguard.url(/.hummercenter.com/i) or
		androguard.url(/.tracksummer.com/i)
		)
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
rule apkeasy_tool_a: repack
{
	meta:
		description = "apkeasy tool deafaulr sert for compiling source code"
condition:
        androguard.certificate.sha1("61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81") or
		androguard.certificate.sha1("0C2440C055C753A8F0493B4E602D3EA0096B1023") or
		androguard.certificate.sha1("485900563D272C46AE118605A47419AC09CA8C11")
		}
rule potential_miners_by_strings_b: miner
{
	meta:
		description = "This rule detects potential miners using set of strings"
		author = "https://koodous.com/analysts/zyrik"
	strings:
        $id001 = "4Cf2TfMKhCgJ2vsM3HeBUnYe52tXrvv8X1ajjuQEMUQ8iU8kvUzCSsCEacxFhEmeb2JgPpQ5chdyw3UiTfUgapJBhBKu2R58FcyCP2RKyq"
        $id002 = "44V8ww9soyFfrivJDfcgmT2gXCFPQDyLFXyS7mEo2xTSaf7NFXAL9usGxrko3aKauBGcwZaF1duCWc2p9eDNt9H7Q8iB7gy"
        $id003 = "43QGgipcHvNLBX3nunZLwVQpF6VbobmGcQKzXzQ5xMfJgzfRBzfXcJHX1tUHcKPm9bcjubrzKqTm69JbQSL4B3f6E3mNCbU"
        $id004 = "45vSqhWgnyRKKjmiUsSpnd14UZpMoVgZWARvyepZY1fEdERMnG6gyzB8ziGB5fCg9cfoKywXdgvXVg1E9bxzPbc8CSE5huQ"
        $id005 = "46yzCCD3Mza9tRj7aqPSaxVbbePtuAeKzf8Ky2eRtcXGcEgCg1iTBio6N4sPmznfgGEUGDoBz5CLxZ2XPTyZu1yoCAG7zt6"
        $id006 = "422QQNhnhX8hmMEkF3TWePWSvKm6DiV7sS3Za2dXrynsJ1w8U6AzwjEdnewdhmP3CDaqvaS6BjEjGMK9mnumtufvLmz5HJi"
        $id007 = "42DEobaAFK67GTxX359z83ecfa2imuqgRdrdhDRo4qGnXU6WijcjmHfQoucNPxQaZjgkkG5DWkahi8QnsXKgapfhRHo4xud"
        $id008 = "43FeFPuaspxAEU7ZGEY93YBmG8nkA1x1Pgg5kTh7mYuLXCzMP3hERey6QBdKKBciuqhsakJD44bGHhJX98V3VjbZ9r1LKzx"
        $id009 = "45oLJdzMCfPFrtz46yqNNyTNKPFRvye5XB94R7sDWvZQZmoyPy6pfk9fdgJaXFs5Jp7F8R8V42UoxjXKE2Ze842Q18Lx24G"
        $id010 = "44yphkVFNewhMGi8LkgfYSSo4gbpnT7uPeGdtwvACMB6S4zY2B6D3iWY9yF7mFX6rbJ3A3fCd8cqJVbW2zYEJLLGEnYfhLy"
        $id011 = "49Bq2bFsvJFAe11SgAZQZjZRn6rE2CXHz4tkoomgx4pZhkJVSUmUHT4ixRWdGX8z2cgJeftiyTEK1U1DW7mEZS8E4dF5hkn"
        $id012 = "4ASDBruxfJ4in134jDC1ysNPjXase7sQwZZfnLCdyVggfsaJB1AxSA8jVnXwLEe1vjBhG7sfpssqMZ8YCSAkuFCELvhUaQ1"
        $id013 = "Q0105005d36e565f5487c1d950e59a04c05c4f410345d460d8bd4d59ca2428fe7b69cf6b787fa92"
        $id014 = "44ea2ae6ec816e7955d27bf6af2f7c2e6ce36c142ee34e428dbcc808af9bc078"
        $id015 = "515b125d8a9fbc944f8652841869335d21fb0a2968c3"
        $id016 = "RHDMXKDoD2aYDwX5PRM0IUfNrQMv9yCR"
        $id017 = "1eUqLvDauJzZUjLlxvEBJfaMXpcCvOum"
        $id018 = "OkcKKX6waOTc0sRFwJXdh5PFTobpRMow"
        $id019 = "6GlWvU4BbBgzJ3wzL3mkJEVazCxxIHjF"
        $id020 = "8LqXh2UY7QzxwK2PrIQLn3iwd7HfuYgt"
        $id021 = "BLAXcU2ALlc06bhhl4Dj64Wbj44hnKYO"
        $id022 = "bLXRob0Mov5Po9c0fSrXexaJkciBo5Dp"
        $id023 = "E2B9t9yVqR62YaRw4wWX3jfadGdxcRfH"
        $id024 = "esp9hnZ3rOao2IadnClF11r6PWtExGAB"
        $id025 = "f4JsDABslmUsqfqa1SqBxbdUFp9h8eAe"
        $id026 = "InSicsHzpAQpeRBTvV2bCRT3J5mK8IoH"
        $id027 = "ITERXYJEQszTERbPanh7CxXanvT64Q5C"
        $id028 = "N09gjytzJzCQzFy9MRuchpT6TzqMXjVB"
        $id029 = "nS4VZBZRmBGNvzfQN57Mu4aodai7Hh9U"
        $id030 = "o2nnEz8ECFPcZvqSInL1Z1xcbyYvpqzD"
        $id031 = "pRdnpY8EOPrnZdDDqYStGOTLNborIkCY"
        $id032 = "tx82bQv1RTVR5V0fe2hUMSkmyNw9zmlS"
        $id033 = "v2RuDMli7TYzHF7ge0lG5VLYUDp5ISM3"
        $id034 = "W9e1JbsYTHqCwImFfAEGfJJigBCWfYv2"
        $id035 = "Xo54zUaiQUexHS1nEkT6b038trLnt0vg"
        $id036 = "XxTxffZJjxU8rLviOim34l5O3MJMWmDK"
        $id037 = "uBiTW6jSZk7mqG4mJRq4TeHMYhwu96it"
        $id038 = "aePxi6MAxNjx4Zrza5XpYaETxzCiCAGD"
        $id039 = "ZjWTajjTeo0IFi1lE3ArPpJ9MCnsimm7"
        $id040 = "pfSLncN8wTEksroVnGo5qE2rlc0zPsu4"
        $id041 = "p3ghDUhs89AhpWiQqh01aBbSFO9BQfR6"
        $id042 = "qqWrKdZTVrXznFYcZ1icdXh3mjROzyhQ"
        $id043 = "ejYytKXlz2qRKYxsHp7yeqPyEF93sMOx"
        $id044 = "VOTOnyFz4gLoYQokkyZ0O2C67UgejX14"
        $id045 = "HtQkBqXwvzRHUdngvFWg1j84fQ62RnVo"
        $id046 = "cJsrc2H0m8rKjzXo4CF7cPLcg6znPogR"
        $id047 = "lRzS5W2NgHybxcbH5BHNnNat4QajQy51"
        $id048 = "9eJhVNC0dT3qgLWnnz0ojYkBJWDZONpO"
        $id049 = "JTGErE8qg0xjlgI8aJckAqX7uamxBCyb"
        $id050 = "ciIJoDEHvWDsFjUHfX7nDMuADREcBMjD"
        $id051 = "ivFo3gzNufGSFc4lAS7dbQecVnEwf2fn"
        $id052 = "nUNBYr6kljQAEVkfLgxRY2UavY6okT4y"
        $id053 = "rD0u5dQUdYEhyHzdUt4b4HFj5OnQfylx"
        $id054 = "sdibwtwKsYZue7Q7yCoKPy7ZwIeweQXw"
        $id055 = "CxHsGJiU1DItubcIa6r7T8bK27a4eUZG"
        $id056 = "NPYVnbZeXgvboqWU0pzUVasryJgShjMU"
        $id057 = "6VLUnZXGvLqDuABUvERNwKObgOPDnB2j"
        $id058 = "YQ1at78RnEjeEiIRzLGAGY9lFo4iHU8v"
        $id059 = "4O99dpG3I4wBLhRLutkoA2cIAkWxqiZl"
        $id060 = "DulPovFs1oAWloQEruJIMlBpsDooMI1f"
        $id061 = "nYt8fRXPWp92u8MHvtdNVOoyuYdfZIdd"
        $id062 = "fwW95bBFO91OKUsz1VhlMEQwxmDBz7XE"
        $id063 = "8SUFoIbdMUfwgDVAXgyyaC5R1k1B2ny1"
        $id064 = "1a0Cej64dYffEiItrLIeiq4GfpPtn0Hf"
        $id065 = "pnkGf8QJ92Z7QEhw8exumIL8HjKCBveQ"
        $id066 = "EjGZOcQjjaAU6sPmgtoUtgfxJSzAI7Id"
        $id067 = "3ARWsJFCmo3Kg13cnr4BAW3fP5uLLoMsbL"
        $id068 = "jPypuxLViIH1ZNallVeg9LqypsYK0wq9"
        $id069 = "ugrZV7MvW9J6Wfa1NgE7qwXFmTHhYorj"
        $id070 = "aX3rvYs5vmuTbT0rr83UDiUD0VolYCkZ"
        $id071 = "1DLnwEX2GUhmRA62aCMAveHPzUN9m2dd"
        $id072 = "8P3iejGFCkXynNojWYArCRBZ21J6zrDy"
        $id073 = "y7cM7qd7ZEEQ6MdkCtDdwo6EcOpe6Oyu"
        $id074 = "dsQIV8MsvvWHB1Q8Ky1faRlpU0qzYVg1"
        $id075 = "fljRO8IOscGvuIX6I2N6agxzVM9XoYXt"
        $id076 = "1a0Cej64dYffEiItrLIeiq4GfpPtn0Hf"
        $id077 = "dzZiMNu2ju00u997BHk2uk6n6GKbtuXw"
        $id078 = "OE4oIwyeXe5YImXY5lDLscoZZrhm9DDN"
        $id079 = "eKoOYNLHEMxcmFXrQnARORLeZo9SMlZR"
        $id080 = "aePxi6MAxNjx4Zrza5XpYaETxzCiCAGD"
        $id081 = "HN0DRyXrOpCbdkyWIZnC7UjMeXvFtkh0"
        $id082 = "1nK3FmVEeZ0bjc6Np1r63wkynuTP3oqU"
        $id083 = "aePxi6MAxNjx4Zrza5XpYaETxzCiCAGD"
        $id084 = "c0aYHt9KgnXUpmZkm7tGPW2rGXl2bM2d"
        $id085 = "bXjy6ex2L7E4nI7RATUXKQKlRVeY8pyw"
        $id086 = "ZPKnEehMXNylSyz6HFP7xBUlCADEIcPy"
        $id087 = "fqJfdzGDvfwbedsKSUGty3VZ9taXxMVw"
        $id088 = "PT13WGgxMmJoaEdMc3dDTDE5Mlp2TjNY"
        $id089 = "Jz0IWB14EmMzZDdMc3dDdnZ4R2tsaDI9"
        $id090 = "PEDk4i0UIq7GsUEAEwXs31dqKjDHUI3z"
        $id091 = "FYEAbFBG3xY5VUtE9GXC56v5UKt4xkoUkb"
        $id092 = "2HujvzmUo2nuRLLqhIHIV4sCEmRw9FIc"
        $id093 = "5xUKpsv5UFOcqf6dToqMDAtBYKn1WavS"
        $id094 = "9AYxnHCZ2H7MwagCSMDwLiSizaSbqhSp"
        $id095 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        $id096 = "anWcowZ0OspSk7SPFH0itFrDrNyCpVXp"
        $id097 = "cLfiFmhE82tUfGodiYgS3U1ewQpMa2nc"
        $id098 = "DUMWz54MXfCcQGUufjx7aeBlGgaurUcU"
        $id099 = "dWzYVbhggge684eSOBSvN7gEoGs9Mjc"
        $id100 = "fz0unvRkvThZ7DcPzxfMnZoTEpZJoblt"
        $id101 = "JCchrP65tMKei1yeLQGtaOdZxXtxZryy"
        $id103 = "o2iHliDUYieOuXz3wME2NjZW79a5apK5"
        $id104 = "oQtjTDL7Jzpj8yTCD8RJMN3cxLt3pXUD"
        $id105 = "QnXbx7vLFIUq9FT0kfNZSjBkUD0GCcqi"
        $id106 = "ZHg7IgsgCYIQLhWEnLVFq06yKedNkKC9"
        $id107 = "eXnvyAQwXxGV80C4fGuiRiDZiDpDaSrf"
        $id108 = "1NeoArmnGyWHKfbje9JNWqw3tquMY7jHCw"
        $id109 = "LA7Ida655adggnBNrMgKfj7ufCwUSBQwZb7"
        $id110 = "BX9yNHd8IZ9oBVGp3ciPBdysVkmAGWv7"
        $id111 = "Vi0mvlm3aS8xDeOTMyD4vvlyPG95dbDZ"
        $id112 = "gidVWyszRjxYBNC1IoxeIDTqSK17ZAT5"
        $id113 = "SmOkuf8IXMjW1WCUeOY2EWPcjt7Ina96"
        $id114 = "lFoT0JKyWO4wh2BX7f5G4Ilg09mlnfoz"
        $link000 = "my.electroneum.com"
        $link001 = "api.electroneum.com"
        $link002 = "api.coinhive.com"
        $link003 = "ftp.coinhive-manager.com"
        $link004 = "coinhive.com"
        $link005 = "coinhiver.com"
        $link006 = "coinhives.com"
        $link007 = "coinhiveproxy.com"
        $link008 = "coinhive-proxy.party"
        $link009 = "coinhive-manager.com"
        $link010 = "coinhive.info"
        $link011 = "coinhive.net"
        $link012 = "coinhive.org"
        $link013 = "apin.monerise.com"
        $link014 = "authedmine.eu"
        $link015 = "authedmine.com"
        $link016 = "50million.club"
        $link017 = "primary.coinhuntr.com"
        $link018 = "api.bitcoin.cz"
        $link019 = "cryptominingfarm.io"
        $link020 = "litecoinpool.org"
        $link021 = "us.litecoinpool.org"
        $link022 = "us2.litecoinpool.org"
        $link023 = "www.rexminer.com/mobil"
        $link024 = "www.megaproxylist.net/appmonerominer/minerxmr.aspx"
        $link025 = "pool.supportxmr.com"
        $link026 = "poolw.etnpooler.com"
        $link027 = "xmr.nanopool.org"
        $link028 = "nyc01.supportxmr.com"
        $link029 = "hk01.supportxmr.com"
        $link030 = "hk02.supportxmr.com"
        $link031 = "fr04.supportxmr.com"
        $link032 = "qrl.herominers.com"
        $link033 = "akgpr.com/Mining"
        $link034 = "www.buyguard.co/sdk/"
        $link035 = "mrpool.net"
        $link036 = "raw.githubusercontent.com/cryptominesetting"
        $link037 = "miner.mobeleader.com/miner.php"
        $link038 = "github.com/C0nw0nk/CoinHive"
        $link039 = "stratum+tcp://litecoinpool.org"
        $link040 = "stratum+tcp://eu.multipool.us"
        $link041 = "stratum+tcp://stratum.bitcoin.cz"
        $link042 = "stratum+tcp://groestlcoin.biz"
        $link043 = "com.puregoldapps.eth.mine"
        $link044 = "api.kanke365.com"
        $link045 = "cnhv.co"
        $link046 = "coin-hive.com"
        $link047 = "coinhive.com"
        $link048 = "authedmine.com"
        $link049 = "api.jsecoin.com"
        $link050 = "load.jsecoin.com"
        $link051 = "server.jsecoin.com"
        $link052 = "miner.pr0gramm.com"
        $link053 = "minemytraffic.com"
        $link054 = "ppoi.org"
        $link055 = "projectpoi.com"
        $link056 = "crypto-loot.com"
        $link057 = "cryptaloot.pro"
        $link058 = "cryptoloot.pro"
        $link059 = "coinerra.com"
        $link060 = "coin-have.com"
        $link061 = "minero.pw"
        $link062 = "minero-proxy-01.now.sh"
        $link063 = "minero-proxy-02.now.sh"
        $link064 = "minero-proxy-03.now.sh"
        $link065 = "api.inwemo.com"
        $link066 = "rocks.io"
        $link067 = "adminer.com"
        $link068 = "ad-miner.com"
        $link069 = "jsccnn.com"
        $link070 = "jscdndel.com"
        $link071 = "coinhiveproxy.com"
        $link072 = "coinblind.com"
        $link073 = "coinnebula.com"
        $link074 = "monerominer.rocks"
        $link075 = "cdn.cloudcoins.co"
        $link076 = "coinlab.biz"
        $link077 = "go.megabanners.cf"
        $link078 = "baiduccdn1.com"
        $link079 = "wsp.marketgid.com"
        $link080 = "papoto.com"
        $link081 = "flare-analytics.com"
        $link082 = "www.sparechange.io"
        $link083 = "static.sparechange.io"
        $link084 = "miner.nablabee.com"
        $link085 = "m.anyfiles.ovh"
        $link086 = "coinimp.com"
        $link087 = "coinimp.net"
        $link088 = "freecontent.bid"
        $link089 = "freecontent.date"
        $link090 = "freecontent.faith"
        $link091 = "freecontent.loan"
        $link092 = "freecontent.racing"
        $link093 = "freecontent.win"
        $link094 = "blockchained.party"
        $link095 = "hostingcloud.download"
        $link096 = "cryptonoter.com"
        $link097 = "mutuza.win"
        $link098 = "crypto-webminer.com"
        $link099 = "cdn.adless.io"
        $link100 = "hegrinhar.com"
        $link101 = "verresof.com"
        $link102 = "hemnes.win"
        $link103 = "tidafors.xyz"
        $link104 = "moneone.ga"
        $link105 = "plexcoin.info"
        $link106 = "www.monkeyminer.net"
        $link107 = "go2.mercy.ga"
        $link108 = "coinpirate.cf"
        $link109 = "d.cpufan.club"
        $link110 = "krb.devphp.org.ua"
        $link111 = "nfwebminer.com"
        $link112 = "cfcdist.gdn"
        $link113 = "node.cfcdist.gdn"
        $link114 = "webxmr.com"
        $link115 = "xmr.mining.best"
        $link116 = "webminepool.com"
        $link117 = "webminepool.tk"
        $link118 = "hive.tubetitties.com"
        $link119 = "playerassets.info"
        $link120 = "tokyodrift.ga"
        $link121 = "webassembly.stream"
        $link122 = "www.webassembly.stream"
        $link123 = "okeyletsgo.ml"
        $link124 = "candid.zone"
        $link125 = "webmine.pro"
        $link126 = "andlache.com"
        $link127 = "bablace.com"
        $link128 = "bewaslac.com"
        $link129 = "biberukalap.com"
        $link130 = "bowithow.com"
        $link131 = "butcalve.com"
        $link132 = "evengparme.com"
        $link133 = "gridiogrid.com"
        $link134 = "hatcalter.com"
        $link135 = "kedtise.com"
        $link136 = "ledinund.com"
        $link137 = "nathetsof.com"
        $link138 = "renhertfo.com"
        $link139 = "rintindown.com"
        $link140 = "sparnove.com"
        $link141 = "witthethim.com"
        $link142 = "1q2w3.fun"
        $link143 = "1q2w3.me"
        $link144 = "bjorksta.men"
        $link145 = "crypto.csgocpu.com"
        $link146 = "noblock.pro"
        $link147 = "miner.cryptobara.com"
        $link148 = "digger.cryptobara.com"
        $link149 = "dev.cryptobara.com"
        $link150 = "reservedoffers.club"
        $link151 = "mine.torrent.pw"
        $link152 = "host.d-ns.ga"
        $link153 = "abc.pema.cl"
        $link154 = "js.nahnoji.cz"
        $link155 = "mine.nahnoji.cz"
        $link156 = "webmine.cz"
        $link157 = "www.webmine.cz"
        $link158 = "intactoffers.club"
        $link159 = "analytics.blue"
        $link160 = "smectapop12.pl"
        $link161 = "berserkpl.net.pl"
        $link162 = "hodlers.party"
        $link163 = "hodling.faith"
        $link164 = "chainblock.science"
        $link165 = "minescripts.info"
        $link166 = "cdn.minescripts.info"
        $link167 = "miner.nablabee.com"
        $link168 = "wss.nablabee.com"
        $link169 = "clickwith.bid"
        $link170 = "dronml.ml"
        $link171 = "niematego.tk"
        $link172 = "tulip18.com"
        $link173 = "p.estream.to"
        $link174 = "didnkinrab.com"
        $link175 = "ledhenone.com"
        $link176 = "losital.ru"
        $link177 = "mebablo.com"
        $link178 = "moonsade.com"
        $link179 = "nebabrop.com"
        $link180 = "pearno.com"
        $link181 = "rintinwa.com"
        $link182 = "willacrit.com"
        $link183 = "www2.adfreetv.ch"
        $link184 = "minr.pw"
        $link185 = "new.minr.pw"
        $link186 = "test.minr.pw"
        $link187 = "staticsfs.host"
        $link188 = "cdn-code.host"
        $link189 = "g-content.bid"
        $link190 = "ad.g-content.bid"
        $link191 = "cdn.static-cnt.bid"
        $link192 = "cnt.statistic.date"
        $link193 = "jquery-uim.download"
        $link194 = "cdn.jquery-uim.download"
        $link195 = "cdn-jquery.host"
        $link196 = "p1.interestingz.pw"
        $link197 = "kippbeak.cf"
        $link198 = "pasoherb.gq"
        $link199 = "axoncoho.tk"
        $link200 = "depttake.ga"
        $link201 = "flophous.cf"
        $link202 = "pr0gram.org"
        $link203 = "authedmine.eu"
        $link204 = "www.monero-miner.com"
        $link205 = "www.datasecu.download"
        $link206 = "www.jquery-cdn.download"
        $link207 = "www.etzbnfuigipwvs.ru"
        $link208 = "www.terethat.ru"
        $link209 = "freshrefresher.com"
        $link210 = "api.pzoifaum.info"
        $link211 = "ws.pzoifaum.info"
        $link212 = "api.bhzejltg.info"
        $link213 = "ws.bhzejltg.info"
        $link214 = "d.cfcnet.top"
        $link215 = "vip.cfcnet.top"
        $link216 = "eu.cfcnet.top"
        $link217 = "as.cfcnet.top"
        $link218 = "us.cfcnet.top"
        $link219 = "eu.cfcdist.loan"
        $link220 = "as.cfcdist.loan"
        $link221 = "us.cfcdist.loan"
        $link222 = "gustaver.ddns.net"
        $link223 = "worker.salon.com"
        $link224 = "s2.appelamule.com"
        $link225 = "mepirtedic.com"
        $link226 = "cdn.streambeam.io"
        $link227 = "adzjzewsma.cf"
        $link228 = "ffinwwfpqi.gq"
        $link229 = "ininmacerad.pro"
        $link230 = "mhiobjnirs.gq"
        $link231 = "open-hive-server-1.pp.ua"
        $link232 = "pool.hws.ru"
        $link233 = "pool.etn.spacepools.org"
        $link234 = "api.aalbbh84.info"
        $link235 = "www.aymcsx.ru"
        $link236 = "aeros01.tk"
        $link237 = "aeros02.tk"
        $link238 = "aeros03.tk"
        $link239 = "aeros04.tk"
        $link240 = "aeros05.tk"
        $link241 = "aeros06.tk"
        $link242 = "aeros07.tk"
        $link243 = "aeros08.tk"
        $link244 = "aeros09.tk"
        $link245 = "aeros10.tk"
        $link246 = "aeros11.tk"
        $link247 = "aeros12.tk"
        $link248 = "npcdn1.now.sh"
        $link249 = "mxcdn2.now.sh"
        $link250 = "sxcdn6.now.sh"
        $link251 = "mxcdn1.now.sh"
        $link252 = "sxcdn02.now.sh"
        $link253 = "sxcdn4.now.sh"
        $link254 = "jqcdn2.herokuapp.com"
        $link255 = "sxcdn1.herokuapp.com"
        $link256 = "sxcdn5.herokuapp.com"
        $link257 = "wpcdn1.herokuapp.com"
        $link258 = "jqcdn01.herokuapp.com"
        $link259 = "jqcdn03.herokuapp.com"
        $link260 = "1q2w3.website"
        $link261 = "video.videos.vidto.me"
        $link262 = "play.play1.videos.vidto.me"
        $link263 = "playe.vidto.se"
        $link264 = "video.streaming.estream.to"
        $link265 = "eth-pocket.de"
        $link266 = "xvideosharing.site"
        $link267 = "bestcoinsignals.com"
        $link268 = "eucsoft.com"
        $link269 = "traviilo.com"
        $link270 = "wasm24.ru"
        $link271 = "xmr.cool"
        $link272 = "api.netflare.info"
        $link273 = "cdnjs.cloudflane.com"
        $link274 = "www.cloudflane.com"
        $link275 = "clgserv.pro"
        $link276 = "hide.ovh"
        $link277 = "graftpool.ovh"
        $link278 = "encoding.ovh"
        $link279 = "altavista.ovh"
        $link280 = "scaleway.ovh"
        $link281 = "nexttime.ovh"
        $link282 = "never.ovh"
        $link283 = "2giga.download"
        $link284 = "support.2giga.link"
        $link285 = "webminerpool.com"
        $link286 = "minercry.pt"
        $link287 = "adplusplus.fr"
        $link288 = "ethtrader.de"
        $link289 = "gobba.myeffect.net"
        $link290 = "bauersagtnein.myeffect.net"
        $link291 = "besti.ga"
        $link292 = "jurty.ml"
        $link293 = "jurtym.cf"
        $link294 = "mfio.cf"
        $link295 = "mwor.gq"
        $link296 = "oei1.gq"
        $link297 = "wordc.ga"
        $link298 = "berateveng.ru"
        $link299 = "ctlrnwbv.ru"
        $link300 = "ermaseuc.ru"
        $link301 = "kdmkauchahynhrs.ru"
        $link302 = "uoldid.ru"
        $link303 = "jqrcdn.download"
        $link304 = "jqassets.download"
        $link305 = "jqcdn.download"
        $link306 = "jquerrycdn.download"
        $link307 = "jqwww.download"
        $link308 = "lightminer.co"
        $link309 = "www.lightminer.co"
        $link310 = "browsermine.com"
        $link311 = "api.browsermine.com"
        $link312 = "mlib.browsermine.com"
        $link313 = "bmst.pw"
        $link314 = "bmnr.pw"
        $link315 = "bmcm.pw"
        $link316 = "bmcm.ml"
        $link317 = "videoplayer2.xyz"
        $link318 = "play.video2.stream.vidzi.tv"
        $link319 = "001.0x1f4b0.com"
        $link320 = "002.0x1f4b0.com"
        $link321 = "003.0x1f4b0.com"
        $link322 = "004.0x1f4b0.com"
        $link323 = "005.0x1f4b0.com"
        $link324 = "006.0x1f4b0.com"
        $link325 = "007.0x1f4b0.com"
        $link326 = "008.0x1f4b0.com"
        $link327 = "authedwebmine.cz"
        $link328 = "www.authedwebmine.cz"
        $link329 = "skencituer.com"
        $link330 = "site.flashx.cc"
        $link331 = "play1.flashx.pw"
        $link332 = "play2.flashx.pw"
        $link333 = "play4.flashx.pw"
        $link334 = "play5.flashx.pw"
        $link335 = "js.vidoza.net"
        $link336 = "mm.zubovskaya-banya.ru"
        $link337 = "mysite.irkdsu.ru"
        $link338 = "play.estream.nu"
        $link339 = "play.estream.to"
        $link340 = "play.estream.xyz"
        $link341 = "play.play.estream.nu"
        $link342 = "play.play.estream.to"
        $link343 = "play.play.estream.xyz"
        $link344 = "play.tainiesonline.pw"
        $link345 = "play.vidzi.tv"
        $link346 = "play.pampopholf.com"
        $link347 = "s3.pampopholf.com"
        $link348 = "play.malictuiar.com"
        $link349 = "s3.malictuiar.com"
        $link350 = "play.play.tainiesonline.stream"
        $link351 = "ocean2.authcaptcha.com"
        $link352 = "rock2.authcaptcha.com"
        $link353 = "stone2.authcaptcha.com"
        $link354 = "sass2.authcaptcha.com"
        $link355 = "sea2.authcaptcha.com"
        $link356 = "play.flowplayer.space"
        $link357 = "play.pc.belicimo.pw"
        $link358 = "play.power.tainiesonline.pw"
        $link359 = "play.s01.vidtodo.pro"
        $link360 = "play.cc.gofile.io"
        $link361 = "wm.yololike.space"
        $link362 = "play.mix.kinostuff.com"
        $link363 = "play.on.animeteatr.ru"
        $link364 = "play.mine.gay-hotvideo.net"
        $link365 = "play.www.intellecthosting.net"
        $link366 = "mytestminer.xyz"
        $link367 = "play.vb.wearesaudis.net"
        $link368 = "flowplayer.space"
        $link369 = "s2.flowplayer.space"
        $link370 = "s3.flowplayer.space"
        $link371 = "thersprens.com"
        $link372 = "s2.thersprens.com"
        $link373 = "s3.thersprens.com"
        $link374 = "play.gramombird.com"
        $link375 = "ugmfvqsu.ru"
        $link376 = "bsyauqwerd.party"
        $link377 = "ccvwtdtwyu.trade"
        $link378 = "baywttgdhe.download"
        $link379 = "pdheuryopd.loan"
        $link380 = "iaheyftbsn.review"
        $link381 = "djfhwosjck.bid"
        $link382 = "najsiejfnc.win"
        $link383 = "zndaowjdnf.stream"
        $link384 = "yqaywudifu.date"
        $link385 = "malictuiar.com"
        $link386 = "proofly.win"
        $link387 = "zminer.zaloapp.com"
        $link388 = "vkcdnservice.com"
        $link389 = "dexim.space"
        $link390 = "acbp0020171456.page.tl"
        $link391 = "vuryua.ru"
        $link392 = "minexmr.stream"
        $link393 = "gitgrub.pro"
        $link394 = "d8acddffe978b5dfcae6.date"
        $link395 = "eth-pocket.com"
        $link396 = "autologica.ga"
        $link397 = "whysoserius.club"
        $link398 = "aster18cdn.nl"
        $link399 = "nerohut.com"
        $link400 = "gnrdomimplementation.com"
        $link401 = "pon.ewtuyytdf45.com"
        $link402 = "hhb123.tk"
        $link403 = "dzizsih.ru"
        $link404 = "nddmcconmqsy.ru"
        $link405 = "silimbompom.com"
        $link406 = "unrummaged.com"
        $link407 = "fruitice.realnetwrk.com"
        $link408 = "synconnector.com"
        $link409 = "toftofcal.com"
        $link410 = "gasolina.ml"
        $link411 = "8jd2lfsq.me"
        $link412 = "afflow.18-plus.net"
        $link413 = "afminer.com"
        $link414 = "aservices.party"
        $link415 = "becanium.com"
        $link416 = "brominer.com"
        $link417 = "cdn-analytics.pl"
        $link418 = "cdn.static-cnt.bid"
        $link419 = "cloudcdn.gdn"
        $link420 = "coin-service.com"
        $link421 = "coinpot.co"
        $link422 = "coinrail.io"
        $link423 = "etacontent.com"
        $link424 = "exdynsrv.com"
        $link425 = "formulawire.com"
        $link426 = "go.bestmobiworld.com"
        $link427 = "goldoffer.online"
        $link428 = "hallaert.online"
        $link429 = "hashing.win"
        $link430 = "igrid.org"
        $link431 = "laserveradedomaina.com"
        $link432 = "machieved.com"
        $link433 = "nametraff.com"
        $link434 = "offerreality.com"
        $link435 = "ogrid.org"
        $link436 = "panelsave.com"
        $link437 = "party-vqgdyvoycc.now.sh"
        $link438 = "pertholin.com"
        $link439 = "premiumstats.xyz"
        $link440 = "serie-vostfr.com"
        $link441 = "salamaleyum.com"
        $link442 = "smartoffer.site"
        $link443 = "stonecalcom.com"
        $link444 = "thewhizmarketing.com"
        $link445 = "thewhizproducts.com"
        $link446 = "thewise.com"
        $link447 = "traffic.tc-clicks.com"
        $link448 = "vcfs6ip5h6.bid"
        $link449 = "web.dle-news.pw"
        $link450 = "webmining.co"
        $link451 = "wp-monero-miner.de"
        $link452 = "wtm.monitoringservice.co"
        $link453 = "xy.nullrefexcep.com"
        $link454 = "yrdrtzmsmt.com"
        $link455 = "wss.rand.com.ru"
        $link456 = "verifier.live"
        $link457 = "jshosting.bid"
        $link458 = "jshosting.date"
        $link459 = "jshosting.download"
        $link460 = "jshosting.faith"
        $link461 = "jshosting.loan"
        $link462 = "jshosting.party"
        $link463 = "jshosting.racing"
        $link464 = "jshosting.review"
        $link465 = "jshosting.science"
        $link466 = "jshosting.stream"
        $link467 = "jshosting.trade"
        $link468 = "jshosting.win"
        $link469 = "freecontent.download"
        $link470 = "freecontent.party"
        $link471 = "freecontent.review"
        $link472 = "freecontent.science"
        $link473 = "freecontent.stream"
        $link474 = "freecontent.trade"
        $link475 = "hostingcloud.bid"
        $link476 = "hostingcloud.date"
        $link477 = "hostingcloud.faith"
        $link478 = "hostingcloud.loan"
        $link479 = "hostingcloud.party"
        $link480 = "hostingcloud.racing"
        $link481 = "hostingcloud.review"
        $link482 = "hostingcloud.science"
        $link483 = "hostingcloud.stream"
        $link484 = "hostingcloud.trade"
        $link485 = "hostingcloud.win"
        $link486 = "minerad.com"
        $link487 = "coin-cube.com"
        $link488 = "coin-services.info"
        $link489 = "service4refresh.info"
        $link490 = "money-maker-script.info"
        $link491 = "money-maker-default.info"
        $link492 = "money-maker-default.info"
        $link493 = "de-ner-mi-nis4.info"
        $link494 = "de-nis-ner-mi-5.info"
        $link495 = "de-mi-nis-ner2.info"
        $link496 = "de-mi-nis-ner.info"
        $link497 = "mi-de-ner-nis3.info"
        $link498 = "s2.soodatmish.com"
        $link499 = "s2.thersprens.com"
        $link500 = "play.feesocrald.com"
        $link501 = "cdn1.pebx.pl"
        $link502 = "play.nexioniect.com"
        $link503 = "play.besstahete.info"
        $link504 = "s2.myregeneaf.com"
        $link505 = "s3.myregeneaf.com"
        $link506 = "reauthenticator.com"
        $link507 = "rock.reauthenticator.com"
        $link508 = "serv1swork.com"
        $link509 = "str1kee.com"
        $link510 = "f1tbit.com"
        $link511 = "g1thub.com"
        $link512 = "swiftmining.win"
        $link513 = "cashbeet.com"
        $link514 = "wmtech.website"
        $link515 = "www.notmining.org"
        $link516 = "coinminingonline.com"
        $link517 = "alflying.bid"
        $link518 = "alflying.date"
        $link519 = "alflying.win"
        $link520 = "anybest.host"
        $link521 = "anybest.pw"
        $link522 = "anybest.site"
        $link523 = "anybest.space"
        $link524 = "dubester.pw"
        $link525 = "dubester.site"
        $link526 = "dubester.space"
        $link527 = "flightsy.bid"
        $link528 = "flightsy.date"
        $link529 = "flightsy.win"
        $link530 = "flighty.win"
        $link531 = "flightzy.bid"
        $link532 = "flightzy.date"
        $link533 = "flightzy.win"
        $link534 = "gettate.date"
        $link535 = "gettate.faith"
        $link536 = "gettate.racing"
        $link537 = "mighbest.host"
        $link538 = "mighbest.pw"
        $link539 = "mighbest.site"
        $link540 = "zymerget.bid"
        $link541 = "zymerget.date"
        $link542 = "zymerget.faith"
        $link543 = "zymerget.party"
        $link544 = "zymerget.stream"
        $link545 = "zymerget.win"
        $link546 = "statdynamic.com"
        $link547 = "alpha.nimiqpool.com"
        $link548 = "api.miner.beeppool.org"
        $link549 = "beatingbytes.com"
        $link550 = "besocial.online"
        $link551 = "beta.nimiqpool.com"
        $link552 = "bulls.nimiqpool.com"
        $link553 = "de1.eu.nimiqpool.com"
        $link554 = "ethmedialab.info"
        $link555 = "feilding.nimiqpool.com"
        $link556 = "foxton.nimiqpool.com"
        $link557 = "ganymed.beeppool.org"
        $link558 = "himatangi.nimiqpool.com"
        $link559 = "levin.nimiqpool.com"
        $link560 = "mine.terorie.com"
        $link561 = "miner-1.team.nimiq.agency"
        $link562 = "miner-10.team.nimiq.agency"
        $link563 = "miner-11.team.nimiq.agency"
        $link564 = "miner-12.team.nimiq.agency"
        $link565 = "miner-13.team.nimiq.agency"
        $link566 = "miner-14.team.nimiq.agency"
        $link567 = "miner-15.team.nimiq.agency"
        $link568 = "miner-16.team.nimiq.agency"
        $link569 = "miner-17.team.nimiq.agency"
        $link570 = "miner-18.team.nimiq.agency"
        $link571 = "miner-19.team.nimiq.agency"
        $link572 = "miner-2.team.nimiq.agency"
        $link573 = "miner-3.team.nimiq.agency"
        $link574 = "miner-4.team.nimiq.agency"
        $link575 = "miner-5.team.nimiq.agency"
        $link576 = "miner-6.team.nimiq.agency"
        $link577 = "miner-7.team.nimiq.agency"
        $link578 = "miner-8.team.nimiq.agency"
        $link579 = "miner-9.team.nimiq.agency"
        $link580 = "miner-deu-1.inf.nimiq.network"
        $link581 = "miner-deu-2.inf.nimiq.network"
        $link582 = "miner-deu-3.inf.nimiq.network"
        $link583 = "miner-deu-4.inf.nimiq.network"
        $link584 = "miner-deu-5.inf.nimiq.network"
        $link585 = "miner-deu-6.inf.nimiq.network"
        $link586 = "miner-deu-7.inf.nimiq.network"
        $link587 = "miner-deu-8.inf.nimiq.network"
        $link588 = "miner.beeppool.org"
        $link589 = "miner.nimiq.com"
        $link590 = "mon-deu-1.inf.nimiq.network"
        $link591 = "mon-deu-2.inf.nimiq.network"
        $link592 = "mon-deu-3.inf.nimiq.network"
        $link593 = "mon-fra-1.inf.nimiq.network"
        $link594 = "mon-fra-2.inf.nimiq.network"
        $link595 = "mon-gbr-1.inf.nimiq.network"
        $link596 = "nimiq.terorie.com"
        $link597 = "nimiqpool.com"
        $link598 = "nimiqtest.ml"
        $link599 = "ninaning.com"
        $link600 = "node.alpha.nimiqpool.com"
        $link601 = "node.nimiqpool.com"
        $link602 = "nodeb.nimiqpool.com"
        $link603 = "nodeone.nimiqpool.com"
        $link604 = "proxy-can-1.inf.nimiq.network"
        $link605 = "proxy-deu-1.inf.nimiq.network"
        $link606 = "proxy-deu-2.inf.nimiq.network"
        $link607 = "proxy-fra-1.inf.nimiq.network"
        $link608 = "proxy-fra-2.inf.nimiq.network"
        $link609 = "proxy-fra-3.inf.nimiq.network"
        $link610 = "proxy-gbr-1.inf.nimiq.network"
        $link611 = "proxy-gbr-2.inf.nimiq.network"
        $link612 = "proxy-pol-1.inf.nimiq.network"
        $link613 = "proxy-pol-2.inf.nimiq.network"
        $link614 = "script.nimiqpool.com"
        $link615 = "seed-1.nimiq-network.com"
        $link616 = "seed-1.nimiq.com"
        $link617 = "seed-1.nimiq.network"
        $link618 = "seed-10.nimiq-network.com"
        $link619 = "seed-10.nimiq.com"
        $link620 = "seed-10.nimiq.network"
        $link621 = "seed-11.nimiq-network.com"
        $link622 = "seed-11.nimiq.com"
        $link623 = "seed-11.nimiq.network"
        $link624 = "seed-12.nimiq-network.com"
        $link625 = "seed-12.nimiq.com"
        $link626 = "seed-12.nimiq.network"
        $link627 = "seed-13.nimiq-network.com"
        $link628 = "seed-13.nimiq.com"
        $link629 = "seed-13.nimiq.network"
        $link630 = "seed-14.nimiq-network.com"
        $link631 = "seed-14.nimiq.com"
        $link632 = "seed-14.nimiq.network"
        $link633 = "seed-15.nimiq-network.com"
        $link634 = "seed-15.nimiq.com"
        $link635 = "seed-15.nimiq.network"
        $link636 = "seed-16.nimiq-network.com"
        $link637 = "seed-16.nimiq.com"
        $link638 = "seed-16.nimiq.network"
        $link639 = "seed-17.nimiq-network.com"
        $link640 = "seed-17.nimiq.com"
        $link641 = "seed-17.nimiq.network"
        $link642 = "seed-18.nimiq-network.com"
        $link643 = "seed-18.nimiq.com"
        $link644 = "seed-18.nimiq.network"
        $link645 = "seed-19.nimiq-network.com"
        $link646 = "seed-19.nimiq.com"
        $link647 = "seed-19.nimiq.network"
        $link648 = "seed-2.nimiq-network.com"
        $link649 = "seed-2.nimiq.com"
        $link650 = "seed-2.nimiq.network"
        $link651 = "seed-20.nimiq-network.com"
        $link652 = "seed-20.nimiq.com"
        $link653 = "seed-20.nimiq.network"
        $link654 = "seed-3.nimiq-network.com"
        $link655 = "seed-3.nimiq.com"
        $link656 = "seed-3.nimiq.network"
        $link657 = "seed-4.nimiq-network.com"
        $link658 = "seed-4.nimiq.com"
        $link659 = "seed-4.nimiq.network"
        $link660 = "seed-5.nimiq-network.com"
        $link661 = "seed-5.nimiq.com"
        $link662 = "seed-5.nimiq.network"
        $link663 = "seed-6.nimiq-network.com"
        $link664 = "seed-6.nimiq.com"
        $link665 = "seed-6.nimiq.network"
        $link666 = "seed-7.nimiq-network.com"
        $link667 = "seed-7.nimiq.com"
        $link668 = "seed-7.nimiq.network"
        $link669 = "seed-8.nimiq-network.com"
        $link670 = "seed-8.nimiq.com"
        $link671 = "seed-8.nimiq.network"
        $link672 = "seed-9.nimiq-network.com"
        $link673 = "seed-9.nimiq.com"
        $link674 = "seed-9.nimiq.network"
        $link675 = "seed-can-1.inf.nimiq.network"
        $link676 = "seed-can-2.inf.nimiq.network"
        $link677 = "seed-deu-1.inf.nimiq.network"
        $link678 = "seed-deu-2.inf.nimiq.network"
        $link679 = "seed-deu-3.inf.nimiq.network"
        $link680 = "seed-deu-4.inf.nimiq.network"
        $link681 = "seed-fra-1.inf.nimiq.network"
        $link682 = "seed-fra-2.inf.nimiq.network"
        $link683 = "seed-fra-3.inf.nimiq.network"
        $link684 = "seed-fra-4.inf.nimiq.network"
        $link685 = "seed-fra-5.inf.nimiq.network"
        $link686 = "seed-fra-6.inf.nimiq.network"
        $link687 = "seed-gbr-1.inf.nimiq.network"
        $link688 = "seed-gbr-2.inf.nimiq.network"
        $link689 = "seed-gbr-3.inf.nimiq.network"
        $link690 = "seed-gbr-4.inf.nimiq.network"
        $link691 = "seed-pol-1.inf.nimiq.network"
        $link692 = "seed-pol-2.inf.nimiq.network"
        $link693 = "seed-pol-3.inf.nimiq.network"
        $link694 = "seed-pol-4.inf.nimiq.network"
        $link695 = "seed.nimiqpool.com"
        $link696 = "seed1.sushipool.com"
        $link697 = "shannon.nimiqpool.com"
        $link698 = "sunnimiq.cf"
        $link699 = "sunnimiq1.cf"
        $link700 = "sunnimiq2.cf"
        $link701 = "sunnimiq3.cf"
        $link702 = "sunnimiq4.cf"
        $link703 = "sunnimiq5.cf"
        $link704 = "sunnimiq6.cf"
        $link705 = "tokomaru.nimiqpool.com"
        $link706 = "whanganui.nimiqpool.com"
        $link707 = "www.besocial.online"
        $link708 = "nimiq.com"
        $link709 = "miner.nimiq.com"
        $link710 = "cdn.nimiq.com"
        $link711 = "jscoinminer.com"
        $link712 = "www.jscoinminer.com"
        $link713 = "azvjudwr.info"
        $link714 = "jroqvbvw.info"
        $link715 = "jyhfuqoh.info"
        $link716 = "kdowqlpt.info"
        $link717 = "xbasfbno.info"
        $link718 = "1beb2a44.space"
        $link719 = "300ca0d0.space"
        $link720 = "310ca263.space"
        $link721 = "320ca3f6.space"
        $link722 = "330ca589.space"
        $link723 = "340ca71c.space"
        $link724 = "360caa42.space"
        $link725 = "370cabd5.space"
        $link726 = "3c0cb3b4.space"
        $link727 = "3d0cb547.space"
        $js001 = "minercry.pt/processor.js"
        $js002 = "lib/crypta.js"
        $js003 = "authedmine.com/lib/authedmine.min.js"
        $js004 = "coin-hive.com/lib/coinhive.min.js"
        $js005 = "coinhive.com/media/miner.htm"
        $js006 = "coinhive.com/lib/coinhive.min.js"
        $js007 = "cryptaloot.pro/lib/crypta.js"
        $js008 = "webminerpool.com/miner.js"
        $js009 = "play.gramombird.com/app.js"
        $js010 = "CoinHive.User("
        $js011 = "CoinHive.Anonymous("
        $js012 = "CoinHive.Token("
        $js013 = "CoinHive"
        $js015 = "miner.start("
        $js016 = "coinhive_site_key"
        $js017 = "MinerPage.prototype.startStopMine("
        $js018 = "Android.onMiningStartedJS()"
        $js019 = "javascript:startminer("
        $js020 = "javascript:startMining()"
        $js021 = "javascript:stopMining()"
        $js022 = "CRLT.Anonymous("
        $js023 = "CoinImp.Anonymous("
        $js024 = "Client.Anonymous("
        $js025 = "NFMiner"
        $js026 = "deepMiner.Anonymous"
        $js027 = "javascript:document.getElementById('mining-start').click()"
        $js028 = "javascript:document.getElementById('mining-stop').click()"
        $lib001 = "libminer.so"
        $lib002 = "libcpuminer.so"
        $lib004 = "libcpuminer-neon.so"
        $lib005 = "libneondetect.so"
        $lib006 = "libjpegso.so"
        $lib007 = "libcpuminerneonpie.so"
        $lib008 = "libcpuminerneon.so"
        $lib009 = "libcpuminerpie.so"
        $lib010 = "libcpuminerx86.so"
        $lib011 = "libMINERWRAPPER.so"
        $lib012 = "libCPUCHECKER.so"
        $lib013 = "minerd"
        $lib014 = "minerd_neon"
        $lib015 = "minerd_regular"
        $lib016 = "libgl-render.so"
        $lib017 = "libminersdk-neondetect.so"
        $lib018 = "libminersdk-x86.so"
        $lib019 = "libminersdk.so"
        $lib020 = "libmonerujo.so"
        $lib021 = "xmrig"
        $api001 = "Lcom/kaching/kingforaday/service/CoinHiveIntentService"
        $api002 = "Lcom/theah64/coinhive/CoinHive"
        $api004 = "Lcom/bing/crymore/ch/model/GlobalConfig"
        $api005 = "Ler/upgrad/jio/jioupgrader/Coinhive"
        $api006 = "Lcom/mobeleader/spsapp/Fragment_Miner"
        $api007 = "Lcom/mobeleader/spsapp/SpsApp"
        $api008 = "Lcom/mobeleader/minerlib/MinerLib"
        $api009 = "Lcom/coinhiveminer/CoinHive"
        $api011 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/CoinHive"
        $api012 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/MoneroMiner"
        $api013 = "Lclub/mymedia/mobileminer/mining/coinhive/MoneroMiner"
        $api014 = "Lclub/mymedia/mobileminer/mining/litecoin/LiteCoinMiner"
        $api015 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/CoinHive"
        $api016 = "Lclub/mymedia/mobileminer/modules/mining/coinhive/MoneroMiner"
        $api017 = "Lclub/mymedia/mobileminer/modules/mining/Miner"
        $api018 = "Lclub/mymedia/mobileminer/modules/mining/litecoin/LiteCoinMiner"
        $api019 = "Luk/co/wardworks/pocketminer/API/LitecoinPool/LitecoinPoolModal"
        $api020 = "Lcom/wiseplay/web/resources/CoinhiveBlock"
        $api021 = "Lcoinminerandroid/coinminer/cma/coinminerandroid"
        $api023 = "Lcom/minergate/miner/Miner"
        $api024 = "Lcom/minergate/miner/services/MinerService"
        $api025 = "startMiner"
        $misc001 = "kingforaday" 
        $misc002 = "fopaminer" 
        $misc003 = "gadgetium" 
        $misc004 = "coinhive" 
        $misc005 = "litecoin" 
        $misc006 = "stratum" 
        $misc007 = "ethereum" 
        $misc008 = "monero" 
        $misc009 = "cpuminer" 
        $misc010 = "cpu-miner" 
        $misc011 = "cpu_miner" 
        $misc012 = "monerise_builder" 
        $misc013 = "moneroocean.stream" 
        $misc014 = "ethonline.site" 
        $misc015 = "mineralt"
	condition:
	androguard.permission(/android.permission.INTERNET/) and 
	(
        androguard.url(/my.electroneum.com/i) or cuckoo.network.dns_lookup(/my.electroneum.com/i) or
        androguard.url(/api.electroneum.com/i) or cuckoo.network.dns_lookup(/api.electroneum.com/i) or
        androguard.url(/api.coinhive.com/i) or cuckoo.network.dns_lookup(/api.coinhive.com/i) or
        androguard.url(/ftp.coinhive-manager.com/i) or cuckoo.network.dns_lookup(/ftp.coinhive-manager.com/i) or
        androguard.url(/coinhive.com/i) or cuckoo.network.dns_lookup(/coinhive.com/i) or
        androguard.url(/coinhiver.com/i) or cuckoo.network.dns_lookup(/coinhiver.com/i) or
        androguard.url(/coinhives.com/i) or cuckoo.network.dns_lookup(/coinhives.com/i) or
        androguard.url(/coinhiveproxy.com/i) or cuckoo.network.dns_lookup(/coinhiveproxy.com/i) or
        androguard.url(/coinhive-proxy.party/i) or cuckoo.network.dns_lookup(/coinhive-proxy.party/i) or
        androguard.url(/coinhive-manager.com/i) or cuckoo.network.dns_lookup(/coinhive-manager.com/i) or
        androguard.url(/coinhive.info/i) or cuckoo.network.dns_lookup(/coinhive.info/i) or
        androguard.url(/coinhive.net/i) or cuckoo.network.dns_lookup(/coinhive.net/i) or
        androguard.url(/coinhive.org/i) or cuckoo.network.dns_lookup(/coinhive.org/i) or
        androguard.url(/apin.monerise.com/i) or cuckoo.network.dns_lookup(/apin.monerise.com/i) or
        androguard.url(/authedmine.eu/i) or cuckoo.network.dns_lookup(/authedmine.eu/i) or
        androguard.url(/authedmine.com/i) or cuckoo.network.dns_lookup(/authedmine.com/i) or
        androguard.url(/50million.club/i) or cuckoo.network.dns_lookup(/50million.club/i) or
        androguard.url(/primary.coinhuntr.com/i) or cuckoo.network.dns_lookup(/primary.coinhuntr.com/i) or
        androguard.url(/api.bitcoin.cz/i) or cuckoo.network.dns_lookup(/api.bitcoin.cz/i) or
        androguard.url(/cryptominingfarm.io/i) or cuckoo.network.dns_lookup(/cryptominingfarm.io/i) or
        androguard.url(/litecoinpool.org/i) or cuckoo.network.dns_lookup(/litecoinpool.org/i) or
        androguard.url(/us.litecoinpool.org/i) or cuckoo.network.dns_lookup(/us.litecoinpool.org/i) or
        androguard.url(/us2.litecoinpool.org/i) or cuckoo.network.dns_lookup(/us2.litecoinpool.org/i) or
        androguard.url(/www.rexminer.com\/mobil/i) or cuckoo.network.dns_lookup(/www.rexminer.com/i) or
        androguard.url(/www.megaproxylist.net\/appmonerominer\/minerxmr.aspx/i) or
        androguard.url(/pool.supportxmr.com/i) or cuckoo.network.dns_lookup(/pool.supportxmr.com/i) or
        androguard.url(/poolw.etnpooler.com/i) or cuckoo.network.dns_lookup(/poolw.etnpooler.com/i) or
        androguard.url(/xmr.nanopool.org/i) or cuckoo.network.dns_lookup(/xmr.nanopool.org/i) or
        androguard.url(/nyc01.supportxmr.com/i) or cuckoo.network.dns_lookup(/nyc01.supportxmr.com/i) or
        androguard.url(/hk01.supportxmr.com/i) or cuckoo.network.dns_lookup(/hk01.supportxmr.com/i) or
        androguard.url(/hk02.supportxmr.com/i) or cuckoo.network.dns_lookup(/hk02.supportxmr.com/i) or
        androguard.url(/fr04.supportxmr.com/i) or cuckoo.network.dns_lookup(/fr04.supportxmr.com/i) or
        androguard.url(/qrl.herominers.com/i) or cuckoo.network.dns_lookup(/qrl.herominers.com/i) or
        androguard.url(/akgpr.com\/Mining/i) or cuckoo.network.dns_lookup(/akgpr.com/i) or
        androguard.url(/www.buyguard.co\/sdk/i) or cuckoo.network.dns_lookup(/www.buyguard.co/i) or
        androguard.url(/mrpool.net/i) or cuckoo.network.dns_lookup(/mrpool.net/i) or
        androguard.url(/raw.githubusercontent.com\/cryptominesetting/i) or
        androguard.url(/miner.mobeleader.com\/miner.php/i) or cuckoo.network.dns_lookup(/miner.mobeleader.com/i) or
        androguard.url(/github.com\/C0nw0nk\/CoinHive/i) or
        androguard.url(/stratum+tcp:\/\/litecoinpool.org/i) or cuckoo.network.dns_lookup(/litecoinpool.org/i) or
        androguard.url(/stratum+tcp:\/\/eu.multipool.us/i) or cuckoo.network.dns_lookup(/eu.multipool.us/i) or
        androguard.url(/stratum+tcp:\/\/stratum.bitcoin.cz/i) or cuckoo.network.dns_lookup(/\stratum.bitcoin.cz/i) or
        androguard.url(/stratum+tcp:\/\/groestlcoin.biz/i) or cuckoo.network.dns_lookup(/groestlcoin.biz/i) or
        androguard.url(/com.puregoldapps.eth.mine/i) or cuckoo.network.dns_lookup(/com.puregoldapps.eth.mine/i) or
        androguard.url(/api.kanke365.com/i) or cuckoo.network.dns_lookup(/api.kanke365.com/i) or
        androguard.url(/cnhv.co/i) or cuckoo.network.dns_lookup(/cnhv.co/i) or
        androguard.url(/coin-hive.com/i) or cuckoo.network.dns_lookup(/coin-hive.com/i) or
        androguard.url(/coinhive.com/i) or cuckoo.network.dns_lookup(/coinhive.com/i) or
        androguard.url(/authedmine.com/i) or cuckoo.network.dns_lookup(/authedmine.com/i) or
        androguard.url(/api.jsecoin.com/i) or cuckoo.network.dns_lookup(/api.jsecoin.com/i) or
        androguard.url(/load.jsecoin.com/i) or cuckoo.network.dns_lookup(/load.jsecoin.com/i) or
        androguard.url(/server.jsecoin.com/i) or cuckoo.network.dns_lookup(/server.jsecoin.com/i) or
        androguard.url(/miner.pr0gramm.com/i) or cuckoo.network.dns_lookup(/miner.pr0gramm.com/i) or
        androguard.url(/minemytraffic.com/i) or cuckoo.network.dns_lookup(/minemytraffic.com/i) or
        androguard.url(/ppoi.org/i) or cuckoo.network.dns_lookup(/ppoi.org/i) or
        androguard.url(/projectpoi.com/i) or cuckoo.network.dns_lookup(/projectpoi.com/i) or
        androguard.url(/crypto-loot.com/i) or cuckoo.network.dns_lookup(/crypto-loot.com/i) or
        androguard.url(/cryptaloot.pro/i) or cuckoo.network.dns_lookup(/cryptaloot.pro/i) or
        androguard.url(/cryptoloot.pro/i) or cuckoo.network.dns_lookup(/cryptoloot.pro/i) or
        androguard.url(/coinerra.com/i) or cuckoo.network.dns_lookup(/coinerra.com/i) or
        androguard.url(/coin-have.com/i) or cuckoo.network.dns_lookup(/coin-have.com/i) or
        androguard.url(/minero.pw/i) or cuckoo.network.dns_lookup(/minero.pw/i) or
        androguard.url(/minero-proxy-01.now.sh/i) or cuckoo.network.dns_lookup(/minero-proxy-01.now.sh/i) or
        androguard.url(/minero-proxy-02.now.sh/i) or cuckoo.network.dns_lookup(/minero-proxy-02.now.sh/i) or
        androguard.url(/minero-proxy-03.now.sh/i) or cuckoo.network.dns_lookup(/minero-proxy-03.now.sh/i) or
        androguard.url(/api.inwemo.com/i) or cuckoo.network.dns_lookup(/api.inwemo.com/i) or
        androguard.url(/rocks.io/i) or cuckoo.network.dns_lookup(/rocks.io/i) or
        androguard.url(/adminer.com/i) or cuckoo.network.dns_lookup(/adminer.com/i) or
        androguard.url(/ad-miner.com/i) or cuckoo.network.dns_lookup(/ad-miner.com/i) or
        androguard.url(/jsccnn.com/i) or cuckoo.network.dns_lookup(/jsccnn.com/i) or
        androguard.url(/jscdndel.com/i) or cuckoo.network.dns_lookup(/jscdndel.com/i) or
        androguard.url(/coinhiveproxy.com/i) or cuckoo.network.dns_lookup(/coinhiveproxy.com/i) or
        androguard.url(/coinblind.com/i) or cuckoo.network.dns_lookup(/coinblind.com/i) or
        androguard.url(/coinnebula.com/i) or cuckoo.network.dns_lookup(/coinnebula.com/i) or
        androguard.url(/monerominer.rocks/i) or cuckoo.network.dns_lookup(/monerominer.rocks/i) or
        androguard.url(/cdn.cloudcoins.co/i) or cuckoo.network.dns_lookup(/cdn.cloudcoins.co/i) or
        androguard.url(/coinlab.biz/i) or cuckoo.network.dns_lookup(/coinlab.biz/i) or
        androguard.url(/go.megabanners.cf/i) or cuckoo.network.dns_lookup(/go.megabanners.cf/i) or
        androguard.url(/baiduccdn1.com/i) or cuckoo.network.dns_lookup(/baiduccdn1.com/i) or
        androguard.url(/wsp.marketgid.com/i) or cuckoo.network.dns_lookup(/wsp.marketgid.com/i) or
        androguard.url(/papoto.com/i) or cuckoo.network.dns_lookup(/papoto.com/i) or
        androguard.url(/flare-analytics.com/i) or cuckoo.network.dns_lookup(/flare-analytics.com/i) or
        androguard.url(/www.sparechange.io/i) or cuckoo.network.dns_lookup(/www.sparechange.io/i) or
        androguard.url(/static.sparechange.io/i) or cuckoo.network.dns_lookup(/static.sparechange.io/i) or
        androguard.url(/miner.nablabee.com/i) or cuckoo.network.dns_lookup(/miner.nablabee.com/i) or
        androguard.url(/m.anyfiles.ovh/i) or cuckoo.network.dns_lookup(/m.anyfiles.ovh/i) or
        androguard.url(/coinimp.com/i) or cuckoo.network.dns_lookup(/coinimp.com/i) or
        androguard.url(/coinimp.net/i) or cuckoo.network.dns_lookup(/coinimp.net/i) or
        androguard.url(/freecontent.bid/i) or cuckoo.network.dns_lookup(/freecontent.bid/i) or
        androguard.url(/freecontent.date/i) or cuckoo.network.dns_lookup(/freecontent.date/i) or
        androguard.url(/freecontent.faith/i) or cuckoo.network.dns_lookup(/freecontent.faith/i) or
        androguard.url(/freecontent.loan/i) or cuckoo.network.dns_lookup(/freecontent.loan/i) or
        androguard.url(/freecontent.racing/i) or cuckoo.network.dns_lookup(/freecontent.racing/i) or
        androguard.url(/freecontent.win/i) or cuckoo.network.dns_lookup(/freecontent.win/i) or
        androguard.url(/blockchained.party/i) or cuckoo.network.dns_lookup(/blockchained.party/i) or
        androguard.url(/hostingcloud.download/i) or cuckoo.network.dns_lookup(/hostingcloud.download/i) or
        androguard.url(/cryptonoter.com/i) or cuckoo.network.dns_lookup(/cryptonoter.com/i) or
        androguard.url(/mutuza.win/i) or cuckoo.network.dns_lookup(/mutuza.win/i) or
        androguard.url(/crypto-webminer.com/i) or cuckoo.network.dns_lookup(/crypto-webminer.com/i) or
        androguard.url(/cdn.adless.io/i) or cuckoo.network.dns_lookup(/cdn.adless.io/i) or
        androguard.url(/hegrinhar.com/i) or cuckoo.network.dns_lookup(/hegrinhar.com/i) or
        androguard.url(/verresof.com/i) or cuckoo.network.dns_lookup(/verresof.com/i) or
        androguard.url(/hemnes.win/i) or cuckoo.network.dns_lookup(/hemnes.win/i) or
        androguard.url(/tidafors.xyz/i) or cuckoo.network.dns_lookup(/tidafors.xyz/i) or
        androguard.url(/moneone.ga/i) or cuckoo.network.dns_lookup(/moneone.ga/i) or
        androguard.url(/plexcoin.info/i) or cuckoo.network.dns_lookup(/plexcoin.info/i) or
        androguard.url(/www.monkeyminer.net/i) or cuckoo.network.dns_lookup(/www.monkeyminer.net/i) or
        androguard.url(/go2.mercy.ga/i) or cuckoo.network.dns_lookup(/go2.mercy.ga/i) or
        androguard.url(/coinpirate.cf/i) or cuckoo.network.dns_lookup(/coinpirate.cf/i) or
        androguard.url(/d.cpufan.club/i) or cuckoo.network.dns_lookup(/d.cpufan.club/i) or
        androguard.url(/krb.devphp.org.ua/i) or cuckoo.network.dns_lookup(/krb.devphp.org.ua/i) or
        androguard.url(/nfwebminer.com/i) or cuckoo.network.dns_lookup(/nfwebminer.com/i) or
        androguard.url(/cfcdist.gdn/i) or cuckoo.network.dns_lookup(/cfcdist.gdn/i) or
        androguard.url(/node.cfcdist.gdn/i) or cuckoo.network.dns_lookup(/node.cfcdist.gdn/i) or
        androguard.url(/webxmr.com/i) or cuckoo.network.dns_lookup(/webxmr.com/i) or
        androguard.url(/xmr.mining.best/i) or cuckoo.network.dns_lookup(/xmr.mining.best/i) or
        androguard.url(/webminepool.com/i) or cuckoo.network.dns_lookup(/webminepool.com/i) or
        androguard.url(/webminepool.tk/i) or cuckoo.network.dns_lookup(/webminepool.tk/i) or
        androguard.url(/hive.tubetitties.com/i) or cuckoo.network.dns_lookup(/hive.tubetitties.com/i) or
        androguard.url(/playerassets.info/i) or cuckoo.network.dns_lookup(/playerassets.info/i) or
        androguard.url(/tokyodrift.ga/i) or cuckoo.network.dns_lookup(/tokyodrift.ga/i) or
        androguard.url(/webassembly.stream/i) or cuckoo.network.dns_lookup(/webassembly.stream/i) or
        androguard.url(/www.webassembly.stream/i) or cuckoo.network.dns_lookup(/www.webassembly.stream/i) or
        androguard.url(/okeyletsgo.ml/i) or cuckoo.network.dns_lookup(/okeyletsgo.ml/i) or
        androguard.url(/candid.zone/i) or cuckoo.network.dns_lookup(/candid.zone/i) or
        androguard.url(/webmine.pro/i) or cuckoo.network.dns_lookup(/webmine.pro/i) or
        androguard.url(/andlache.com/i) or cuckoo.network.dns_lookup(/andlache.com/i) or
        androguard.url(/bablace.com/i) or cuckoo.network.dns_lookup(/bablace.com/i) or
        androguard.url(/bewaslac.com/i) or cuckoo.network.dns_lookup(/bewaslac.com/i) or
        androguard.url(/biberukalap.com/i) or cuckoo.network.dns_lookup(/biberukalap.com/i) or
        androguard.url(/bowithow.com/i) or cuckoo.network.dns_lookup(/bowithow.com/i) or
        androguard.url(/butcalve.com/i) or cuckoo.network.dns_lookup(/butcalve.com/i) or
        androguard.url(/evengparme.com/i) or cuckoo.network.dns_lookup(/evengparme.com/i) or
        androguard.url(/gridiogrid.com/i) or cuckoo.network.dns_lookup(/gridiogrid.com/i) or
        androguard.url(/hatcalter.com/i) or cuckoo.network.dns_lookup(/hatcalter.com/i) or
        androguard.url(/kedtise.com/i) or cuckoo.network.dns_lookup(/kedtise.com/i) or
        androguard.url(/ledinund.com/i) or cuckoo.network.dns_lookup(/ledinund.com/i) or
        androguard.url(/nathetsof.com/i) or cuckoo.network.dns_lookup(/nathetsof.com/i) or
        androguard.url(/renhertfo.com/i) or cuckoo.network.dns_lookup(/renhertfo.com/i) or
        androguard.url(/rintindown.com/i) or cuckoo.network.dns_lookup(/rintindown.com/i) or
        androguard.url(/sparnove.com/i) or cuckoo.network.dns_lookup(/sparnove.com/i) or
        androguard.url(/witthethim.com/i) or cuckoo.network.dns_lookup(/witthethim.com/i) or
        androguard.url(/1q2w3.fun/i) or cuckoo.network.dns_lookup(/1q2w3.fun/i) or
        androguard.url(/1q2w3.me/i) or cuckoo.network.dns_lookup(/1q2w3.me/i) or
        androguard.url(/bjorksta.men/i) or cuckoo.network.dns_lookup(/bjorksta.men/i) or
        androguard.url(/crypto.csgocpu.com/i) or cuckoo.network.dns_lookup(/crypto.csgocpu.com/i) or
        androguard.url(/noblock.pro/i) or cuckoo.network.dns_lookup(/noblock.pro/i) or
        androguard.url(/miner.cryptobara.com/i) or cuckoo.network.dns_lookup(/miner.cryptobara.com/i) or
        androguard.url(/digger.cryptobara.com/i) or cuckoo.network.dns_lookup(/digger.cryptobara.com/i) or
        androguard.url(/dev.cryptobara.com/i) or cuckoo.network.dns_lookup(/dev.cryptobara.com/i) or
        androguard.url(/reservedoffers.club/i) or cuckoo.network.dns_lookup(/reservedoffers.club/i) or
        androguard.url(/mine.torrent.pw/i) or cuckoo.network.dns_lookup(/mine.torrent.pw/i) or
        androguard.url(/host.d-ns.ga/i) or cuckoo.network.dns_lookup(/host.d-ns.ga/i) or
        androguard.url(/abc.pema.cl/i) or cuckoo.network.dns_lookup(/abc.pema.cl/i) or
        androguard.url(/js.nahnoji.cz/i) or cuckoo.network.dns_lookup(/js.nahnoji.cz/i) or
        androguard.url(/mine.nahnoji.cz/i) or cuckoo.network.dns_lookup(/mine.nahnoji.cz/i) or
        androguard.url(/webmine.cz/i) or cuckoo.network.dns_lookup(/webmine.cz/i) or
        androguard.url(/www.webmine.cz/i) or cuckoo.network.dns_lookup(/www.webmine.cz/i) or
        androguard.url(/intactoffers.club/i) or cuckoo.network.dns_lookup(/intactoffers.club/i) or
        androguard.url(/analytics.blue/i) or cuckoo.network.dns_lookup(/analytics.blue/i) or
        androguard.url(/smectapop12.pl/i) or cuckoo.network.dns_lookup(/smectapop12.pl/i) or
        androguard.url(/berserkpl.net.pl/i) or cuckoo.network.dns_lookup(/berserkpl.net.pl/i) or
        androguard.url(/hodlers.party/i) or cuckoo.network.dns_lookup(/hodlers.party/i) or
        androguard.url(/hodling.faith/i) or cuckoo.network.dns_lookup(/hodling.faith/i) or
        androguard.url(/chainblock.science/i) or cuckoo.network.dns_lookup(/chainblock.science/i) or
        androguard.url(/minescripts.info/i) or cuckoo.network.dns_lookup(/minescripts.info/i) or
        androguard.url(/cdn.minescripts.info/i) or cuckoo.network.dns_lookup(/cdn.minescripts.info/i) or
        androguard.url(/miner.nablabee.com/i) or cuckoo.network.dns_lookup(/miner.nablabee.com/i) or
        androguard.url(/wss.nablabee.com/i) or cuckoo.network.dns_lookup(/wss.nablabee.com/i) or
        androguard.url(/clickwith.bid/i) or cuckoo.network.dns_lookup(/clickwith.bid/i) or
        androguard.url(/dronml.ml/i) or cuckoo.network.dns_lookup(/dronml.ml/i) or
        androguard.url(/niematego.tk/i) or cuckoo.network.dns_lookup(/niematego.tk/i) or
        androguard.url(/tulip18.com/i) or cuckoo.network.dns_lookup(/tulip18.com/i) or
        androguard.url(/p.estream.to/i) or cuckoo.network.dns_lookup(/p.estream.to/i) or
        androguard.url(/didnkinrab.com/i) or cuckoo.network.dns_lookup(/didnkinrab.com/i) or
        androguard.url(/ledhenone.com/i) or cuckoo.network.dns_lookup(/ledhenone.com/i) or
        androguard.url(/losital.ru/i) or cuckoo.network.dns_lookup(/losital.ru/i) or
        androguard.url(/mebablo.com/i) or cuckoo.network.dns_lookup(/mebablo.com/i) or
        androguard.url(/moonsade.com/i) or cuckoo.network.dns_lookup(/moonsade.com/i) or
        androguard.url(/nebabrop.com/i) or cuckoo.network.dns_lookup(/nebabrop.com/i) or
        androguard.url(/pearno.com/i) or cuckoo.network.dns_lookup(/pearno.com/i) or
        androguard.url(/rintinwa.com/i) or cuckoo.network.dns_lookup(/rintinwa.com/i) or
        androguard.url(/willacrit.com/i) or cuckoo.network.dns_lookup(/willacrit.com/i) or
        androguard.url(/www2.adfreetv.ch/i) or cuckoo.network.dns_lookup(/www2.adfreetv.ch/i) or
        androguard.url(/minr.pw/i) or cuckoo.network.dns_lookup(/minr.pw/i) or
        androguard.url(/new.minr.pw/i) or cuckoo.network.dns_lookup(/new.minr.pw/i) or
        androguard.url(/test.minr.pw/i) or cuckoo.network.dns_lookup(/test.minr.pw/i) or
        androguard.url(/staticsfs.host/i) or cuckoo.network.dns_lookup(/staticsfs.host/i) or
        androguard.url(/cdn-code.host/i) or cuckoo.network.dns_lookup(/cdn-code.host/i) or
        androguard.url(/g-content.bid/i) or cuckoo.network.dns_lookup(/g-content.bid/i) or
        androguard.url(/ad.g-content.bid/i) or cuckoo.network.dns_lookup(/ad.g-content.bid/i) or
        androguard.url(/cdn.static-cnt.bid/i) or cuckoo.network.dns_lookup(/cdn.static-cnt.bid/i) or
        androguard.url(/cnt.statistic.date/i) or cuckoo.network.dns_lookup(/cnt.statistic.date/i) or
        androguard.url(/jquery-uim.download/i) or cuckoo.network.dns_lookup(/jquery-uim.download/i) or
        androguard.url(/cdn.jquery-uim.download/i) or cuckoo.network.dns_lookup(/cdn.jquery-uim.download/i) or
        androguard.url(/cdn-jquery.host/i) or cuckoo.network.dns_lookup(/cdn-jquery.host/i) or
        androguard.url(/p1.interestingz.pw/i) or cuckoo.network.dns_lookup(/p1.interestingz.pw/i) or
        androguard.url(/kippbeak.cf/i) or cuckoo.network.dns_lookup(/kippbeak.cf/i) or
        androguard.url(/pasoherb.gq/i) or cuckoo.network.dns_lookup(/pasoherb.gq/i) or
        androguard.url(/axoncoho.tk/i) or cuckoo.network.dns_lookup(/axoncoho.tk/i) or
        androguard.url(/depttake.ga/i) or cuckoo.network.dns_lookup(/depttake.ga/i) or
        androguard.url(/flophous.cf/i) or cuckoo.network.dns_lookup(/flophous.cf/i) or
        androguard.url(/pr0gram.org/i) or cuckoo.network.dns_lookup(/pr0gram.org/i) or
        androguard.url(/authedmine.eu/i) or cuckoo.network.dns_lookup(/authedmine.eu/i) or
        androguard.url(/www.monero-miner.com/i) or cuckoo.network.dns_lookup(/www.monero-miner.com/i) or
        androguard.url(/www.datasecu.download/i) or cuckoo.network.dns_lookup(/www.datasecu.download/i) or
        androguard.url(/www.jquery-cdn.download/i) or cuckoo.network.dns_lookup(/www.jquery-cdn.download/i) or
        androguard.url(/www.etzbnfuigipwvs.ru/i) or cuckoo.network.dns_lookup(/www.etzbnfuigipwvs.ru/i) or
        androguard.url(/www.terethat.ru/i) or cuckoo.network.dns_lookup(/www.terethat.ru/i) or
        androguard.url(/freshrefresher.com/i) or cuckoo.network.dns_lookup(/freshrefresher.com/i) or
        androguard.url(/api.pzoifaum.info/i) or cuckoo.network.dns_lookup(/api.pzoifaum.info/i) or
        androguard.url(/ws.pzoifaum.info/i) or cuckoo.network.dns_lookup(/ws.pzoifaum.info/i) or
        androguard.url(/api.bhzejltg.info/i) or cuckoo.network.dns_lookup(/api.bhzejltg.info/i) or
        androguard.url(/ws.bhzejltg.info/i) or cuckoo.network.dns_lookup(/ws.bhzejltg.info/i) or
        androguard.url(/d.cfcnet.top/i) or cuckoo.network.dns_lookup(/d.cfcnet.top/i) or
        androguard.url(/vip.cfcnet.top/i) or cuckoo.network.dns_lookup(/vip.cfcnet.top/i) or
        androguard.url(/eu.cfcnet.top/i) or cuckoo.network.dns_lookup(/eu.cfcnet.top/i) or
        androguard.url(/as.cfcnet.top/i) or cuckoo.network.dns_lookup(/as.cfcnet.top/i) or
        androguard.url(/us.cfcnet.top/i) or cuckoo.network.dns_lookup(/us.cfcnet.top/i) or
        androguard.url(/eu.cfcdist.loan/i) or cuckoo.network.dns_lookup(/eu.cfcdist.loan/i) or
        androguard.url(/as.cfcdist.loan/i) or cuckoo.network.dns_lookup(/as.cfcdist.loan/i) or
        androguard.url(/us.cfcdist.loan/i) or cuckoo.network.dns_lookup(/us.cfcdist.loan/i) or
        androguard.url(/gustaver.ddns.net/i) or cuckoo.network.dns_lookup(/gustaver.ddns.net/i) or
        androguard.url(/worker.salon.com/i) or cuckoo.network.dns_lookup(/worker.salon.com/i) or
        androguard.url(/s2.appelamule.com/i) or cuckoo.network.dns_lookup(/s2.appelamule.com/i) or
        androguard.url(/mepirtedic.com/i) or cuckoo.network.dns_lookup(/mepirtedic.com/i) or
        androguard.url(/cdn.streambeam.io/i) or cuckoo.network.dns_lookup(/cdn.streambeam.io/i) or
        androguard.url(/adzjzewsma.cf/i) or cuckoo.network.dns_lookup(/adzjzewsma.cf/i) or
        androguard.url(/ffinwwfpqi.gq/i) or cuckoo.network.dns_lookup(/ffinwwfpqi.gq/i) or
        androguard.url(/ininmacerad.pro/i) or cuckoo.network.dns_lookup(/ininmacerad.pro/i) or
        androguard.url(/mhiobjnirs.gq/i) or cuckoo.network.dns_lookup(/mhiobjnirs.gq/i) or
        androguard.url(/open-hive-server-1.pp.ua/i) or cuckoo.network.dns_lookup(/open-hive-server-1.pp.ua/i) or
        androguard.url(/pool.hws.ru/i) or cuckoo.network.dns_lookup(/pool.hws.ru/i) or
        androguard.url(/pool.etn.spacepools.org/i) or cuckoo.network.dns_lookup(/pool.etn.spacepools.org/i) or
        androguard.url(/api.aalbbh84.info/i) or cuckoo.network.dns_lookup(/api.aalbbh84.info/i) or
        androguard.url(/www.aymcsx.ru/i) or cuckoo.network.dns_lookup(/www.aymcsx.ru/i) or
        androguard.url(/aeros01.tk/i) or cuckoo.network.dns_lookup(/aeros01.tk/i) or
        androguard.url(/aeros02.tk/i) or cuckoo.network.dns_lookup(/aeros02.tk/i) or
        androguard.url(/aeros03.tk/i) or cuckoo.network.dns_lookup(/aeros03.tk/i) or
        androguard.url(/aeros04.tk/i) or cuckoo.network.dns_lookup(/aeros04.tk/i) or
        androguard.url(/aeros05.tk/i) or cuckoo.network.dns_lookup(/aeros05.tk/i) or
        androguard.url(/aeros06.tk/i) or cuckoo.network.dns_lookup(/aeros06.tk/i) or
        androguard.url(/aeros07.tk/i) or cuckoo.network.dns_lookup(/aeros07.tk/i) or
        androguard.url(/aeros08.tk/i) or cuckoo.network.dns_lookup(/aeros08.tk/i) or
        androguard.url(/aeros09.tk/i) or cuckoo.network.dns_lookup(/aeros09.tk/i) or
        androguard.url(/aeros10.tk/i) or cuckoo.network.dns_lookup(/aeros10.tk/i) or
        androguard.url(/aeros11.tk/i) or cuckoo.network.dns_lookup(/aeros11.tk/i) or
        androguard.url(/aeros12.tk/i) or cuckoo.network.dns_lookup(/aeros12.tk/i) or
        androguard.url(/npcdn1.now.sh/i) or cuckoo.network.dns_lookup(/npcdn1.now.sh/i) or
        androguard.url(/mxcdn2.now.sh/i) or cuckoo.network.dns_lookup(/mxcdn2.now.sh/i) or
        androguard.url(/sxcdn6.now.sh/i) or cuckoo.network.dns_lookup(/sxcdn6.now.sh/i) or
        androguard.url(/mxcdn1.now.sh/i) or cuckoo.network.dns_lookup(/mxcdn1.now.sh/i) or
        androguard.url(/sxcdn02.now.sh/i) or cuckoo.network.dns_lookup(/sxcdn02.now.sh/i) or
        androguard.url(/sxcdn4.now.sh/i) or cuckoo.network.dns_lookup(/sxcdn4.now.sh/i) or
        androguard.url(/jqcdn2.herokuapp.com/i) or cuckoo.network.dns_lookup(/jqcdn2.herokuapp.com/i) or
        androguard.url(/sxcdn1.herokuapp.com/i) or cuckoo.network.dns_lookup(/sxcdn1.herokuapp.com/i) or
        androguard.url(/sxcdn5.herokuapp.com/i) or cuckoo.network.dns_lookup(/sxcdn5.herokuapp.com/i) or
        androguard.url(/wpcdn1.herokuapp.com/i) or cuckoo.network.dns_lookup(/wpcdn1.herokuapp.com/i) or
        androguard.url(/jqcdn01.herokuapp.com/i) or cuckoo.network.dns_lookup(/jqcdn01.herokuapp.com/i) or
        androguard.url(/jqcdn03.herokuapp.com/i) or cuckoo.network.dns_lookup(/jqcdn03.herokuapp.com/i) or
        androguard.url(/1q2w3.website/i) or cuckoo.network.dns_lookup(/1q2w3.website/i) or
        androguard.url(/video.videos.vidto.me/i) or cuckoo.network.dns_lookup(/video.videos.vidto.me/i) or
        androguard.url(/play.play1.videos.vidto.me/i) or cuckoo.network.dns_lookup(/play.play1.videos.vidto.me/i) or
        androguard.url(/playe.vidto.se/i) or cuckoo.network.dns_lookup(/playe.vidto.se/i) or
        androguard.url(/video.streaming.estream.to/i) or cuckoo.network.dns_lookup(/video.streaming.estream.to/i) or
        androguard.url(/eth-pocket.de/i) or cuckoo.network.dns_lookup(/eth-pocket.de/i) or
        androguard.url(/xvideosharing.site/i) or cuckoo.network.dns_lookup(/xvideosharing.site/i) or
        androguard.url(/bestcoinsignals.com/i) or cuckoo.network.dns_lookup(/bestcoinsignals.com/i) or
        androguard.url(/eucsoft.com/i) or cuckoo.network.dns_lookup(/eucsoft.com/i) or
        androguard.url(/traviilo.com/i) or cuckoo.network.dns_lookup(/traviilo.com/i) or
        androguard.url(/wasm24.ru/i) or cuckoo.network.dns_lookup(/wasm24.ru/i) or
        androguard.url(/xmr.cool/i) or cuckoo.network.dns_lookup(/xmr.cool/i) or
        androguard.url(/api.netflare.info/i) or cuckoo.network.dns_lookup(/api.netflare.info/i) or
        androguard.url(/cdnjs.cloudflane.com/i) or cuckoo.network.dns_lookup(/cdnjs.cloudflane.com/i) or
        androguard.url(/www.cloudflane.com/i) or cuckoo.network.dns_lookup(/www.cloudflane.com/i) or
        androguard.url(/clgserv.pro/i) or cuckoo.network.dns_lookup(/clgserv.pro/i) or
        androguard.url(/hide.ovh/i) or cuckoo.network.dns_lookup(/hide.ovh/i) or
        androguard.url(/graftpool.ovh/i) or cuckoo.network.dns_lookup(/graftpool.ovh/i) or
        androguard.url(/encoding.ovh/i) or cuckoo.network.dns_lookup(/encoding.ovh/i) or
        androguard.url(/altavista.ovh/i) or cuckoo.network.dns_lookup(/altavista.ovh/i) or
        androguard.url(/scaleway.ovh/i) or cuckoo.network.dns_lookup(/scaleway.ovh/i) or
        androguard.url(/nexttime.ovh/i) or cuckoo.network.dns_lookup(/nexttime.ovh/i) or
        androguard.url(/never.ovh/i) or cuckoo.network.dns_lookup(/never.ovh/i) or
        androguard.url(/2giga.download/i) or cuckoo.network.dns_lookup(/2giga.download/i) or
        androguard.url(/support.2giga.link/i) or cuckoo.network.dns_lookup(/support.2giga.link/i) or
        androguard.url(/webminerpool.com/i) or cuckoo.network.dns_lookup(/webminerpool.com/i) or
        androguard.url(/minercry.pt/i) or cuckoo.network.dns_lookup(/minercry.pt/i) or
        androguard.url(/adplusplus.fr/i) or cuckoo.network.dns_lookup(/adplusplus.fr/i) or
        androguard.url(/ethtrader.de/i) or cuckoo.network.dns_lookup(/ethtrader.de/i) or
        androguard.url(/gobba.myeffect.net/i) or cuckoo.network.dns_lookup(/gobba.myeffect.net/i) or
        androguard.url(/bauersagtnein.myeffect.net/i) or cuckoo.network.dns_lookup(/bauersagtnein.myeffect.net/i) or
        androguard.url(/besti.ga/i) or cuckoo.network.dns_lookup(/besti.ga/i) or
        androguard.url(/jurty.ml/i) or cuckoo.network.dns_lookup(/jurty.ml/i) or
        androguard.url(/jurtym.cf/i) or cuckoo.network.dns_lookup(/jurtym.cf/i) or
        androguard.url(/mfio.cf/i) or cuckoo.network.dns_lookup(/mfio.cf/i) or
        androguard.url(/mwor.gq/i) or cuckoo.network.dns_lookup(/mwor.gq/i) or
        androguard.url(/oei1.gq/i) or cuckoo.network.dns_lookup(/oei1.gq/i) or
        androguard.url(/wordc.ga/i) or cuckoo.network.dns_lookup(/wordc.ga/i) or
        androguard.url(/berateveng.ru/i) or cuckoo.network.dns_lookup(/berateveng.ru/i) or
        androguard.url(/ctlrnwbv.ru/i) or cuckoo.network.dns_lookup(/ctlrnwbv.ru/i) or
        androguard.url(/ermaseuc.ru/i) or cuckoo.network.dns_lookup(/ermaseuc.ru/i) or
        androguard.url(/kdmkauchahynhrs.ru/i) or cuckoo.network.dns_lookup(/kdmkauchahynhrs.ru/i) or
        androguard.url(/uoldid.ru/i) or cuckoo.network.dns_lookup(/uoldid.ru/i) or
        androguard.url(/jqrcdn.download/i) or cuckoo.network.dns_lookup(/jqrcdn.download/i) or
        androguard.url(/jqassets.download/i) or cuckoo.network.dns_lookup(/jqassets.download/i) or
        androguard.url(/jqcdn.download/i) or cuckoo.network.dns_lookup(/jqcdn.download/i) or
        androguard.url(/jquerrycdn.download/i) or cuckoo.network.dns_lookup(/jquerrycdn.download/i) or
        androguard.url(/jqwww.download/i) or cuckoo.network.dns_lookup(/jqwww.download/i) or
        androguard.url(/lightminer.co/i) or cuckoo.network.dns_lookup(/lightminer.co/i) or
        androguard.url(/www.lightminer.co/i) or cuckoo.network.dns_lookup(/www.lightminer.co/i) or
        androguard.url(/browsermine.com/i) or cuckoo.network.dns_lookup(/browsermine.com/i) or
        androguard.url(/api.browsermine.com/i) or cuckoo.network.dns_lookup(/api.browsermine.com/i) or
        androguard.url(/mlib.browsermine.com/i) or cuckoo.network.dns_lookup(/mlib.browsermine.com/i) or
        androguard.url(/bmst.pw/i) or cuckoo.network.dns_lookup(/bmst.pw/i) or
        androguard.url(/bmnr.pw/i) or cuckoo.network.dns_lookup(/bmnr.pw/i) or
        androguard.url(/bmcm.pw/i) or cuckoo.network.dns_lookup(/bmcm.pw/i) or
        androguard.url(/bmcm.ml/i) or cuckoo.network.dns_lookup(/bmcm.ml/i) or
        androguard.url(/videoplayer2.xyz/i) or cuckoo.network.dns_lookup(/videoplayer2.xyz/i) or
        androguard.url(/play.video2.stream.vidzi.tv/i) or cuckoo.network.dns_lookup(/play.video2.stream.vidzi.tv/i) or
        androguard.url(/001.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/001.0x1f4b0.com/i) or
        androguard.url(/002.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/002.0x1f4b0.com/i) or
        androguard.url(/003.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/003.0x1f4b0.com/i) or
        androguard.url(/004.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/004.0x1f4b0.com/i) or
        androguard.url(/005.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/005.0x1f4b0.com/i) or
        androguard.url(/006.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/006.0x1f4b0.com/i) or
        androguard.url(/007.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/007.0x1f4b0.com/i) or
        androguard.url(/008.0x1f4b0.com/i) or cuckoo.network.dns_lookup(/008.0x1f4b0.com/i) or
        androguard.url(/authedwebmine.cz/i) or cuckoo.network.dns_lookup(/authedwebmine.cz/i) or
        androguard.url(/www.authedwebmine.cz/i) or cuckoo.network.dns_lookup(/www.authedwebmine.cz/i) or
        androguard.url(/skencituer.com/i) or cuckoo.network.dns_lookup(/skencituer.com/i) or
        androguard.url(/site.flashx.cc/i) or cuckoo.network.dns_lookup(/site.flashx.cc/i) or
        androguard.url(/play1.flashx.pw/i) or cuckoo.network.dns_lookup(/play1.flashx.pw/i) or
        androguard.url(/play2.flashx.pw/i) or cuckoo.network.dns_lookup(/play2.flashx.pw/i) or
        androguard.url(/play4.flashx.pw/i) or cuckoo.network.dns_lookup(/play4.flashx.pw/i) or
        androguard.url(/play5.flashx.pw/i) or cuckoo.network.dns_lookup(/play5.flashx.pw/i) or
        androguard.url(/js.vidoza.net/i) or cuckoo.network.dns_lookup(/js.vidoza.net/i) or
        androguard.url(/mm.zubovskaya-banya.ru/i) or cuckoo.network.dns_lookup(/mm.zubovskaya-banya.ru/i) or
        androguard.url(/mysite.irkdsu.ru/i) or cuckoo.network.dns_lookup(/mysite.irkdsu.ru/i) or
        androguard.url(/play.estream.nu/i) or cuckoo.network.dns_lookup(/play.estream.nu/i) or
        androguard.url(/play.estream.to/i) or cuckoo.network.dns_lookup(/play.estream.to/i) or
        androguard.url(/play.estream.xyz/i) or cuckoo.network.dns_lookup(/play.estream.xyz/i) or
        androguard.url(/play.play.estream.nu/i) or cuckoo.network.dns_lookup(/play.play.estream.nu/i) or
        androguard.url(/play.play.estream.to/i) or cuckoo.network.dns_lookup(/play.play.estream.to/i) or
        androguard.url(/play.play.estream.xyz/i) or cuckoo.network.dns_lookup(/play.play.estream.xyz/i) or
        androguard.url(/play.tainiesonline.pw/i) or cuckoo.network.dns_lookup(/play.tainiesonline.pw/i) or
        androguard.url(/play.vidzi.tv/i) or cuckoo.network.dns_lookup(/play.vidzi.tv/i) or
        androguard.url(/play.pampopholf.com/i) or cuckoo.network.dns_lookup(/play.pampopholf.com/i) or
        androguard.url(/s3.pampopholf.com/i) or cuckoo.network.dns_lookup(/s3.pampopholf.com/i) or
        androguard.url(/play.malictuiar.com/i) or cuckoo.network.dns_lookup(/play.malictuiar.com/i) or
        androguard.url(/s3.malictuiar.com/i) or cuckoo.network.dns_lookup(/s3.malictuiar.com/i) or
        androguard.url(/play.play.tainiesonline.stream/i) or cuckoo.network.dns_lookup(/play.play.tainiesonline.stream/i) or
        androguard.url(/ocean2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/ocean2.authcaptcha.com/i) or
        androguard.url(/rock2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/rock2.authcaptcha.com/i) or
        androguard.url(/stone2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/stone2.authcaptcha.com/i) or
        androguard.url(/sass2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/sass2.authcaptcha.com/i) or
        androguard.url(/sea2.authcaptcha.com/i) or cuckoo.network.dns_lookup(/sea2.authcaptcha.com/i) or
        androguard.url(/play.flowplayer.space/i) or cuckoo.network.dns_lookup(/play.flowplayer.space/i) or
        androguard.url(/play.pc.belicimo.pw/i) or cuckoo.network.dns_lookup(/play.pc.belicimo.pw/i) or
        androguard.url(/play.power.tainiesonline.pw/i) or cuckoo.network.dns_lookup(/play.power.tainiesonline.pw/i) or
        androguard.url(/play.s01.vidtodo.pro/i) or cuckoo.network.dns_lookup(/play.s01.vidtodo.pro/i) or
        androguard.url(/play.cc.gofile.io/i) or cuckoo.network.dns_lookup(/play.cc.gofile.io/i) or
        androguard.url(/wm.yololike.space/i) or cuckoo.network.dns_lookup(/wm.yololike.space/i) or
        androguard.url(/play.mix.kinostuff.com/i) or cuckoo.network.dns_lookup(/play.mix.kinostuff.com/i) or
        androguard.url(/play.on.animeteatr.ru/i) or cuckoo.network.dns_lookup(/play.on.animeteatr.ru/i) or
        androguard.url(/play.mine.gay-hotvideo.net/i) or cuckoo.network.dns_lookup(/play.mine.gay-hotvideo.net/i) or
        androguard.url(/play.www.intellecthosting.net/i) or cuckoo.network.dns_lookup(/play.www.intellecthosting.net/i) or
        androguard.url(/mytestminer.xyz/i) or cuckoo.network.dns_lookup(/mytestminer.xyz/i) or
        androguard.url(/play.vb.wearesaudis.net/i) or cuckoo.network.dns_lookup(/play.vb.wearesaudis.net/i) or
        androguard.url(/flowplayer.space/i) or cuckoo.network.dns_lookup(/flowplayer.space/i) or
        androguard.url(/s2.flowplayer.space/i) or cuckoo.network.dns_lookup(/s2.flowplayer.space/i) or
        androguard.url(/s3.flowplayer.space/i) or cuckoo.network.dns_lookup(/s3.flowplayer.space/i) or
        androguard.url(/thersprens.com/i) or cuckoo.network.dns_lookup(/thersprens.com/i) or
        androguard.url(/s2.thersprens.com/i) or cuckoo.network.dns_lookup(/s2.thersprens.com/i) or
        androguard.url(/s3.thersprens.com/i) or cuckoo.network.dns_lookup(/s3.thersprens.com/i) or
        androguard.url(/play.gramombird.com/i) or cuckoo.network.dns_lookup(/play.gramombird.com/i) or
        androguard.url(/ugmfvqsu.ru/i) or cuckoo.network.dns_lookup(/ugmfvqsu.ru/i) or
        androguard.url(/bsyauqwerd.party/i) or cuckoo.network.dns_lookup(/bsyauqwerd.party/i) or
        androguard.url(/ccvwtdtwyu.trade/i) or cuckoo.network.dns_lookup(/ccvwtdtwyu.trade/i) or
        androguard.url(/baywttgdhe.download/i) or cuckoo.network.dns_lookup(/baywttgdhe.download/i) or
        androguard.url(/pdheuryopd.loan/i) or cuckoo.network.dns_lookup(/pdheuryopd.loan/i) or
        androguard.url(/iaheyftbsn.review/i) or cuckoo.network.dns_lookup(/iaheyftbsn.review/i) or
        androguard.url(/djfhwosjck.bid/i) or cuckoo.network.dns_lookup(/djfhwosjck.bid/i) or
        androguard.url(/najsiejfnc.win/i) or cuckoo.network.dns_lookup(/najsiejfnc.win/i) or
        androguard.url(/zndaowjdnf.stream/i) or cuckoo.network.dns_lookup(/zndaowjdnf.stream/i) or
        androguard.url(/yqaywudifu.date/i) or cuckoo.network.dns_lookup(/yqaywudifu.date/i) or
        androguard.url(/malictuiar.com/i) or cuckoo.network.dns_lookup(/malictuiar.com/i) or
        androguard.url(/proofly.win/i) or cuckoo.network.dns_lookup(/proofly.win/i) or
        androguard.url(/zminer.zaloapp.com/i) or cuckoo.network.dns_lookup(/zminer.zaloapp.com/i) or
        androguard.url(/vkcdnservice.com/i) or cuckoo.network.dns_lookup(/vkcdnservice.com/i) or
        androguard.url(/dexim.space/i) or cuckoo.network.dns_lookup(/dexim.space/i) or
        androguard.url(/acbp0020171456.page.tl/i) or cuckoo.network.dns_lookup(/acbp0020171456.page.tl/i) or
        androguard.url(/vuryua.ru/i) or cuckoo.network.dns_lookup(/vuryua.ru/i) or
        androguard.url(/minexmr.stream/i) or cuckoo.network.dns_lookup(/minexmr.stream/i) or
        androguard.url(/gitgrub.pro/i) or cuckoo.network.dns_lookup(/gitgrub.pro/i) or
        androguard.url(/d8acddffe978b5dfcae6.date/i) or cuckoo.network.dns_lookup(/d8acddffe978b5dfcae6.date/i) or
        androguard.url(/eth-pocket.com/i) or cuckoo.network.dns_lookup(/eth-pocket.com/i) or
        androguard.url(/autologica.ga/i) or cuckoo.network.dns_lookup(/autologica.ga/i) or
        androguard.url(/whysoserius.club/i) or cuckoo.network.dns_lookup(/whysoserius.club/i) or
        androguard.url(/aster18cdn.nl/i) or cuckoo.network.dns_lookup(/aster18cdn.nl/i) or
        androguard.url(/nerohut.com/i) or cuckoo.network.dns_lookup(/nerohut.com/i) or
        androguard.url(/gnrdomimplementation.com/i) or cuckoo.network.dns_lookup(/gnrdomimplementation.com/i) or
        androguard.url(/pon.ewtuyytdf45.com/i) or cuckoo.network.dns_lookup(/pon.ewtuyytdf45.com/i) or
        androguard.url(/hhb123.tk/i) or cuckoo.network.dns_lookup(/hhb123.tk/i) or
        androguard.url(/dzizsih.ru/i) or cuckoo.network.dns_lookup(/dzizsih.ru/i) or
        androguard.url(/nddmcconmqsy.ru/i) or cuckoo.network.dns_lookup(/nddmcconmqsy.ru/i) or
        androguard.url(/silimbompom.com/i) or cuckoo.network.dns_lookup(/silimbompom.com/i) or
        androguard.url(/unrummaged.com/i) or cuckoo.network.dns_lookup(/unrummaged.com/i) or
        androguard.url(/fruitice.realnetwrk.com/i) or cuckoo.network.dns_lookup(/fruitice.realnetwrk.com/i) or
        androguard.url(/synconnector.com/i) or cuckoo.network.dns_lookup(/synconnector.com/i) or
        androguard.url(/toftofcal.com/i) or cuckoo.network.dns_lookup(/toftofcal.com/i) or
        androguard.url(/gasolina.ml/i) or cuckoo.network.dns_lookup(/gasolina.ml/i) or
        androguard.url(/8jd2lfsq.me/i) or cuckoo.network.dns_lookup(/8jd2lfsq.me/i) or
        androguard.url(/afflow.18-plus.net/i) or cuckoo.network.dns_lookup(/afflow.18-plus.net/i) or
        androguard.url(/afminer.com/i) or cuckoo.network.dns_lookup(/afminer.com/i) or
        androguard.url(/aservices.party/i) or cuckoo.network.dns_lookup(/aservices.party/i) or
        androguard.url(/becanium.com/i) or cuckoo.network.dns_lookup(/becanium.com/i) or
        androguard.url(/brominer.com/i) or cuckoo.network.dns_lookup(/brominer.com/i) or
        androguard.url(/cdn-analytics.pl/i) or cuckoo.network.dns_lookup(/cdn-analytics.pl/i) or
        androguard.url(/cdn.static-cnt.bid/i) or cuckoo.network.dns_lookup(/cdn.static-cnt.bid/i) or
        androguard.url(/cloudcdn.gdn/i) or cuckoo.network.dns_lookup(/cloudcdn.gdn/i) or
        androguard.url(/coin-service.com/i) or cuckoo.network.dns_lookup(/coin-service.com/i) or
        androguard.url(/coinpot.co/i) or cuckoo.network.dns_lookup(/coinpot.co/i) or
        androguard.url(/coinrail.io/i) or cuckoo.network.dns_lookup(/coinrail.io/i) or
        androguard.url(/etacontent.com/i) or cuckoo.network.dns_lookup(/etacontent.com/i) or
        androguard.url(/exdynsrv.com/i) or cuckoo.network.dns_lookup(/exdynsrv.com/i) or
        androguard.url(/formulawire.com/i) or cuckoo.network.dns_lookup(/formulawire.com/i) or
        androguard.url(/go.bestmobiworld.com/i) or cuckoo.network.dns_lookup(/go.bestmobiworld.com/i) or
        androguard.url(/goldoffer.online/i) or cuckoo.network.dns_lookup(/goldoffer.online/i) or
        androguard.url(/hallaert.online/i) or cuckoo.network.dns_lookup(/hallaert.online/i) or
        androguard.url(/hashing.win/i) or cuckoo.network.dns_lookup(/hashing.win/i) or
        androguard.url(/igrid.org/i) or cuckoo.network.dns_lookup(/igrid.org/i) or
        androguard.url(/laserveradedomaina.com/i) or cuckoo.network.dns_lookup(/laserveradedomaina.com/i) or
        androguard.url(/machieved.com/i) or cuckoo.network.dns_lookup(/machieved.com/i) or
        androguard.url(/nametraff.com/i) or cuckoo.network.dns_lookup(/nametraff.com/i) or
        androguard.url(/offerreality.com/i) or cuckoo.network.dns_lookup(/offerreality.com/i) or
        androguard.url(/ogrid.org/i) or cuckoo.network.dns_lookup(/ogrid.org/i) or
        androguard.url(/panelsave.com/i) or cuckoo.network.dns_lookup(/panelsave.com/i) or
        androguard.url(/party-vqgdyvoycc.now.sh/i) or cuckoo.network.dns_lookup(/party-vqgdyvoycc.now.sh/i) or
        androguard.url(/pertholin.com/i) or cuckoo.network.dns_lookup(/pertholin.com/i) or
        androguard.url(/premiumstats.xyz/i) or cuckoo.network.dns_lookup(/premiumstats.xyz/i) or
        androguard.url(/serie-vostfr.com/i) or cuckoo.network.dns_lookup(/serie-vostfr.com/i) or
        androguard.url(/salamaleyum.com/i) or cuckoo.network.dns_lookup(/salamaleyum.com/i) or
        androguard.url(/smartoffer.site/i) or cuckoo.network.dns_lookup(/smartoffer.site/i) or
        androguard.url(/stonecalcom.com/i) or cuckoo.network.dns_lookup(/stonecalcom.com/i) or
        androguard.url(/thewhizmarketing.com/i) or cuckoo.network.dns_lookup(/thewhizmarketing.com/i) or
        androguard.url(/thewhizproducts.com/i) or cuckoo.network.dns_lookup(/thewhizproducts.com/i) or
        androguard.url(/thewise.com/i) or cuckoo.network.dns_lookup(/thewise.com/i) or
        androguard.url(/traffic.tc-clicks.com/i) or cuckoo.network.dns_lookup(/traffic.tc-clicks.com/i) or
        androguard.url(/vcfs6ip5h6.bid/i) or cuckoo.network.dns_lookup(/vcfs6ip5h6.bid/i) or
        androguard.url(/web.dle-news.pw/i) or cuckoo.network.dns_lookup(/web.dle-news.pw/i) or
        androguard.url(/webmining.co/i) or cuckoo.network.dns_lookup(/webmining.co/i) or
        androguard.url(/wp-monero-miner.de/i) or cuckoo.network.dns_lookup(/wp-monero-miner.de/i) or
        androguard.url(/wtm.monitoringservice.co/i) or cuckoo.network.dns_lookup(/wtm.monitoringservice.co/i) or
        androguard.url(/xy.nullrefexcep.com/i) or cuckoo.network.dns_lookup(/xy.nullrefexcep.com/i) or
        androguard.url(/yrdrtzmsmt.com/i) or cuckoo.network.dns_lookup(/yrdrtzmsmt.com/i) or
        androguard.url(/wss.rand.com.ru/i) or cuckoo.network.dns_lookup(/wss.rand.com.ru/i) or
        androguard.url(/verifier.live/i) or cuckoo.network.dns_lookup(/verifier.live/i) or
        androguard.url(/jshosting.bid/i) or cuckoo.network.dns_lookup(/jshosting.bid/i) or
        androguard.url(/jshosting.date/i) or cuckoo.network.dns_lookup(/jshosting.date/i) or
        androguard.url(/jshosting.download/i) or cuckoo.network.dns_lookup(/jshosting.download/i) or
        androguard.url(/jshosting.faith/i) or cuckoo.network.dns_lookup(/jshosting.faith/i) or
        androguard.url(/jshosting.loan/i) or cuckoo.network.dns_lookup(/jshosting.loan/i) or
        androguard.url(/jshosting.party/i) or cuckoo.network.dns_lookup(/jshosting.party/i) or
        androguard.url(/jshosting.racing/i) or cuckoo.network.dns_lookup(/jshosting.racing/i) or
        androguard.url(/jshosting.review/i) or cuckoo.network.dns_lookup(/jshosting.review/i) or
        androguard.url(/jshosting.science/i) or cuckoo.network.dns_lookup(/jshosting.science/i) or
        androguard.url(/jshosting.stream/i) or cuckoo.network.dns_lookup(/jshosting.stream/i) or
        androguard.url(/jshosting.trade/i) or cuckoo.network.dns_lookup(/jshosting.trade/i) or
        androguard.url(/jshosting.win/i) or cuckoo.network.dns_lookup(/jshosting.win/i) or
        androguard.url(/freecontent.download/i) or cuckoo.network.dns_lookup(/freecontent.download/i) or
        androguard.url(/freecontent.party/i) or cuckoo.network.dns_lookup(/freecontent.party/i) or
        androguard.url(/freecontent.review/i) or cuckoo.network.dns_lookup(/freecontent.review/i) or
        androguard.url(/freecontent.science/i) or cuckoo.network.dns_lookup(/freecontent.science/i) or
        androguard.url(/freecontent.stream/i) or cuckoo.network.dns_lookup(/freecontent.stream/i) or
        androguard.url(/freecontent.trade/i) or cuckoo.network.dns_lookup(/freecontent.trade/i) or
        androguard.url(/hostingcloud.bid/i) or cuckoo.network.dns_lookup(/hostingcloud.bid/i) or
        androguard.url(/hostingcloud.date/i) or cuckoo.network.dns_lookup(/hostingcloud.date/i) or
        androguard.url(/hostingcloud.faith/i) or cuckoo.network.dns_lookup(/hostingcloud.faith/i) or
        androguard.url(/hostingcloud.loan/i) or cuckoo.network.dns_lookup(/hostingcloud.loan/i) or
        androguard.url(/hostingcloud.party/i) or cuckoo.network.dns_lookup(/hostingcloud.party/i) or
        androguard.url(/hostingcloud.racing/i) or cuckoo.network.dns_lookup(/hostingcloud.racing/i) or
        androguard.url(/hostingcloud.review/i) or cuckoo.network.dns_lookup(/hostingcloud.review/i) or
        androguard.url(/hostingcloud.science/i) or cuckoo.network.dns_lookup(/hostingcloud.science/i) or
        androguard.url(/hostingcloud.stream/i) or cuckoo.network.dns_lookup(/hostingcloud.stream/i) or
        androguard.url(/hostingcloud.trade/i) or cuckoo.network.dns_lookup(/hostingcloud.trade/i) or
        androguard.url(/hostingcloud.win/i) or cuckoo.network.dns_lookup(/hostingcloud.win/i) or
        androguard.url(/minerad.com/i) or cuckoo.network.dns_lookup(/minerad.com/i) or
        androguard.url(/coin-cube.com/i) or cuckoo.network.dns_lookup(/coin-cube.com/i) or
        androguard.url(/coin-services.info/i) or cuckoo.network.dns_lookup(/coin-services.info/i) or
        androguard.url(/service4refresh.info/i) or cuckoo.network.dns_lookup(/service4refresh.info/i) or
        androguard.url(/money-maker-script.info/i) or cuckoo.network.dns_lookup(/money-maker-script.info/i) or
        androguard.url(/money-maker-default.info/i) or cuckoo.network.dns_lookup(/money-maker-default.info/i) or
        androguard.url(/money-maker-default.info/i) or cuckoo.network.dns_lookup(/money-maker-default.info/i) or
        androguard.url(/de-ner-mi-nis4.info/i) or cuckoo.network.dns_lookup(/de-ner-mi-nis4.info/i) or
        androguard.url(/de-nis-ner-mi-5.info/i) or cuckoo.network.dns_lookup(/de-nis-ner-mi-5.info/i) or
        androguard.url(/de-mi-nis-ner2.info/i) or cuckoo.network.dns_lookup(/de-mi-nis-ner2.info/i) or
        androguard.url(/de-mi-nis-ner.info/i) or cuckoo.network.dns_lookup(/de-mi-nis-ner.info/i) or
        androguard.url(/mi-de-ner-nis3.info/i) or cuckoo.network.dns_lookup(/mi-de-ner-nis3.info/i) or
        androguard.url(/s2.soodatmish.com/i) or cuckoo.network.dns_lookup(/s2.soodatmish.com/i) or
        androguard.url(/s2.thersprens.com/i) or cuckoo.network.dns_lookup(/s2.thersprens.com/i) or
        androguard.url(/play.feesocrald.com/i) or cuckoo.network.dns_lookup(/play.feesocrald.com/i) or
        androguard.url(/cdn1.pebx.pl/i) or cuckoo.network.dns_lookup(/cdn1.pebx.pl/i) or
        androguard.url(/play.nexioniect.com/i) or cuckoo.network.dns_lookup(/play.nexioniect.com/i) or
        androguard.url(/play.besstahete.info/i) or cuckoo.network.dns_lookup(/play.besstahete.info/i) or
        androguard.url(/s2.myregeneaf.com/i) or cuckoo.network.dns_lookup(/s2.myregeneaf.com/i) or
        androguard.url(/s3.myregeneaf.com/i) or cuckoo.network.dns_lookup(/s3.myregeneaf.com/i) or
        androguard.url(/reauthenticator.com/i) or cuckoo.network.dns_lookup(/reauthenticator.com/i) or
        androguard.url(/rock.reauthenticator.com/i) or cuckoo.network.dns_lookup(/rock.reauthenticator.com/i) or
        androguard.url(/serv1swork.com/i) or cuckoo.network.dns_lookup(/serv1swork.com/i) or
        androguard.url(/str1kee.com/i) or cuckoo.network.dns_lookup(/str1kee.com/i) or
        androguard.url(/f1tbit.com/i) or cuckoo.network.dns_lookup(/f1tbit.com/i) or
        androguard.url(/g1thub.com/i) or cuckoo.network.dns_lookup(/g1thub.com/i) or
        androguard.url(/swiftmining.win/i) or cuckoo.network.dns_lookup(/swiftmining.win/i) or
        androguard.url(/cashbeet.com/i) or cuckoo.network.dns_lookup(/cashbeet.com/i) or
        androguard.url(/wmtech.website/i) or cuckoo.network.dns_lookup(/wmtech.website/i) or
        androguard.url(/www.notmining.org/i) or cuckoo.network.dns_lookup(/www.notmining.org/i) or
        androguard.url(/coinminingonline.com/i) or cuckoo.network.dns_lookup(/coinminingonline.com/i) or
        androguard.url(/alflying.bid/i) or cuckoo.network.dns_lookup(/alflying.bid/i) or
        androguard.url(/alflying.date/i) or cuckoo.network.dns_lookup(/alflying.date/i) or
        androguard.url(/alflying.win/i) or cuckoo.network.dns_lookup(/alflying.win/i) or
        androguard.url(/anybest.host/i) or cuckoo.network.dns_lookup(/anybest.host/i) or
        androguard.url(/anybest.pw/i) or cuckoo.network.dns_lookup(/anybest.pw/i) or
        androguard.url(/anybest.site/i) or cuckoo.network.dns_lookup(/anybest.site/i) or
        androguard.url(/anybest.space/i) or cuckoo.network.dns_lookup(/anybest.space/i) or
        androguard.url(/dubester.pw/i) or cuckoo.network.dns_lookup(/dubester.pw/i) or
        androguard.url(/dubester.site/i) or cuckoo.network.dns_lookup(/dubester.site/i) or
        androguard.url(/dubester.space/i) or cuckoo.network.dns_lookup(/dubester.space/i) or
        androguard.url(/flightsy.bid/i) or cuckoo.network.dns_lookup(/flightsy.bid/i) or
        androguard.url(/flightsy.date/i) or cuckoo.network.dns_lookup(/flightsy.date/i) or
        androguard.url(/flightsy.win/i) or cuckoo.network.dns_lookup(/flightsy.win/i) or
        androguard.url(/flighty.win/i) or cuckoo.network.dns_lookup(/flighty.win/i) or
        androguard.url(/flightzy.bid/i) or cuckoo.network.dns_lookup(/flightzy.bid/i) or
        androguard.url(/flightzy.date/i) or cuckoo.network.dns_lookup(/flightzy.date/i) or
        androguard.url(/flightzy.win/i) or cuckoo.network.dns_lookup(/flightzy.win/i) or
        androguard.url(/gettate.date/i) or cuckoo.network.dns_lookup(/gettate.date/i) or
        androguard.url(/gettate.faith/i) or cuckoo.network.dns_lookup(/gettate.faith/i) or
        androguard.url(/gettate.racing/i) or cuckoo.network.dns_lookup(/gettate.racing/i) or
        androguard.url(/mighbest.host/i) or cuckoo.network.dns_lookup(/mighbest.host/i) or
        androguard.url(/mighbest.pw/i) or cuckoo.network.dns_lookup(/mighbest.pw/i) or
        androguard.url(/mighbest.site/i) or cuckoo.network.dns_lookup(/mighbest.site/i) or
        androguard.url(/zymerget.bid/i) or cuckoo.network.dns_lookup(/zymerget.bid/i) or
        androguard.url(/zymerget.date/i) or cuckoo.network.dns_lookup(/zymerget.date/i) or
        androguard.url(/zymerget.faith/i) or cuckoo.network.dns_lookup(/zymerget.faith/i) or
        androguard.url(/zymerget.party/i) or cuckoo.network.dns_lookup(/zymerget.party/i) or
        androguard.url(/zymerget.stream/i) or cuckoo.network.dns_lookup(/zymerget.stream/i) or
        androguard.url(/zymerget.win/i) or cuckoo.network.dns_lookup(/zymerget.win/i) or
        androguard.url(/statdynamic.com/i) or cuckoo.network.dns_lookup(/statdynamic.com/i) or
        androguard.url(/alpha.nimiqpool.com/i) or cuckoo.network.dns_lookup(/alpha.nimiqpool.com/i) or
        androguard.url(/api.miner.beeppool.org/i) or cuckoo.network.dns_lookup(/api.miner.beeppool.org/i) or
        androguard.url(/beatingbytes.com/i) or cuckoo.network.dns_lookup(/beatingbytes.com/i) or
        androguard.url(/besocial.online/i) or cuckoo.network.dns_lookup(/besocial.online/i) or
        androguard.url(/beta.nimiqpool.com/i) or cuckoo.network.dns_lookup(/beta.nimiqpool.com/i) or
        androguard.url(/bulls.nimiqpool.com/i) or cuckoo.network.dns_lookup(/bulls.nimiqpool.com/i) or
        androguard.url(/de1.eu.nimiqpool.com/i) or cuckoo.network.dns_lookup(/de1.eu.nimiqpool.com/i) or
        androguard.url(/ethmedialab.info/i) or cuckoo.network.dns_lookup(/ethmedialab.info/i) or
        androguard.url(/feilding.nimiqpool.com/i) or cuckoo.network.dns_lookup(/feilding.nimiqpool.com/i) or
        androguard.url(/foxton.nimiqpool.com/i) or cuckoo.network.dns_lookup(/foxton.nimiqpool.com/i) or
        androguard.url(/ganymed.beeppool.org/i) or cuckoo.network.dns_lookup(/ganymed.beeppool.org/i) or
        androguard.url(/himatangi.nimiqpool.com/i) or cuckoo.network.dns_lookup(/himatangi.nimiqpool.com/i) or
        androguard.url(/levin.nimiqpool.com/i) or cuckoo.network.dns_lookup(/levin.nimiqpool.com/i) or
        androguard.url(/mine.terorie.com/i) or cuckoo.network.dns_lookup(/mine.terorie.com/i) or
        androguard.url(/miner-1.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-1.team.nimiq.agency/i) or
        androguard.url(/miner-10.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-10.team.nimiq.agency/i) or
        androguard.url(/miner-11.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-11.team.nimiq.agency/i) or
        androguard.url(/miner-12.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-12.team.nimiq.agency/i) or
        androguard.url(/miner-13.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-13.team.nimiq.agency/i) or
        androguard.url(/miner-14.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-14.team.nimiq.agency/i) or
        androguard.url(/miner-15.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-15.team.nimiq.agency/i) or
        androguard.url(/miner-16.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-16.team.nimiq.agency/i) or
        androguard.url(/miner-17.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-17.team.nimiq.agency/i) or
        androguard.url(/miner-18.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-18.team.nimiq.agency/i) or
        androguard.url(/miner-19.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-19.team.nimiq.agency/i) or
        androguard.url(/miner-2.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-2.team.nimiq.agency/i) or
        androguard.url(/miner-3.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-3.team.nimiq.agency/i) or
        androguard.url(/miner-4.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-4.team.nimiq.agency/i) or
        androguard.url(/miner-5.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-5.team.nimiq.agency/i) or
        androguard.url(/miner-6.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-6.team.nimiq.agency/i) or
        androguard.url(/miner-7.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-7.team.nimiq.agency/i) or
        androguard.url(/miner-8.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-8.team.nimiq.agency/i) or
        androguard.url(/miner-9.team.nimiq.agency/i) or cuckoo.network.dns_lookup(/miner-9.team.nimiq.agency/i) or
        androguard.url(/miner-deu-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-1.inf.nimiq.network/i) or
        androguard.url(/miner-deu-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-2.inf.nimiq.network/i) or
        androguard.url(/miner-deu-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-3.inf.nimiq.network/i) or
        androguard.url(/miner-deu-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-4.inf.nimiq.network/i) or
        androguard.url(/miner-deu-5.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-5.inf.nimiq.network/i) or
        androguard.url(/miner-deu-6.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-6.inf.nimiq.network/i) or
        androguard.url(/miner-deu-7.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-7.inf.nimiq.network/i) or
        androguard.url(/miner-deu-8.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/miner-deu-8.inf.nimiq.network/i) or
        androguard.url(/miner.beeppool.org/i) or cuckoo.network.dns_lookup(/miner.beeppool.org/i) or
        androguard.url(/miner.nimiq.com/i) or cuckoo.network.dns_lookup(/miner.nimiq.com/i) or
        androguard.url(/mon-deu-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-deu-1.inf.nimiq.network/i) or
        androguard.url(/mon-deu-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-deu-2.inf.nimiq.network/i) or
        androguard.url(/mon-deu-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-deu-3.inf.nimiq.network/i) or
        androguard.url(/mon-fra-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-fra-1.inf.nimiq.network/i) or
        androguard.url(/mon-fra-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-fra-2.inf.nimiq.network/i) or
        androguard.url(/mon-gbr-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/mon-gbr-1.inf.nimiq.network/i) or
        androguard.url(/nimiq.terorie.com/i) or cuckoo.network.dns_lookup(/nimiq.terorie.com/i) or
        androguard.url(/nimiqpool.com/i) or cuckoo.network.dns_lookup(/nimiqpool.com/i) or
        androguard.url(/nimiqtest.ml/i) or cuckoo.network.dns_lookup(/nimiqtest.ml/i) or
        androguard.url(/ninaning.com/i) or cuckoo.network.dns_lookup(/ninaning.com/i) or
        androguard.url(/node.alpha.nimiqpool.com/i) or cuckoo.network.dns_lookup(/node.alpha.nimiqpool.com/i) or
        androguard.url(/node.nimiqpool.com/i) or cuckoo.network.dns_lookup(/node.nimiqpool.com/i) or
        androguard.url(/nodeb.nimiqpool.com/i) or cuckoo.network.dns_lookup(/nodeb.nimiqpool.com/i) or
        androguard.url(/nodeone.nimiqpool.com/i) or cuckoo.network.dns_lookup(/nodeone.nimiqpool.com/i) or
        androguard.url(/proxy-can-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-can-1.inf.nimiq.network/i) or
        androguard.url(/proxy-deu-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-deu-1.inf.nimiq.network/i) or
        androguard.url(/proxy-deu-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-deu-2.inf.nimiq.network/i) or
        androguard.url(/proxy-fra-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-fra-1.inf.nimiq.network/i) or
        androguard.url(/proxy-fra-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-fra-2.inf.nimiq.network/i) or
        androguard.url(/proxy-fra-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-fra-3.inf.nimiq.network/i) or
        androguard.url(/proxy-gbr-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-gbr-1.inf.nimiq.network/i) or
        androguard.url(/proxy-gbr-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-gbr-2.inf.nimiq.network/i) or
        androguard.url(/proxy-pol-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-pol-1.inf.nimiq.network/i) or
        androguard.url(/proxy-pol-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/proxy-pol-2.inf.nimiq.network/i) or
        androguard.url(/script.nimiqpool.com/i) or cuckoo.network.dns_lookup(/script.nimiqpool.com/i) or
        androguard.url(/seed-1.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-1.nimiq-network.com/i) or
        androguard.url(/seed-1.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-1.nimiq.com/i) or
        androguard.url(/seed-1.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-1.nimiq.network/i) or
        androguard.url(/seed-10.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-10.nimiq-network.com/i) or
        androguard.url(/seed-10.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-10.nimiq.com/i) or
        androguard.url(/seed-10.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-10.nimiq.network/i) or
        androguard.url(/seed-11.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-11.nimiq-network.com/i) or
        androguard.url(/seed-11.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-11.nimiq.com/i) or
        androguard.url(/seed-11.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-11.nimiq.network/i) or
        androguard.url(/seed-12.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-12.nimiq-network.com/i) or
        androguard.url(/seed-12.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-12.nimiq.com/i) or
        androguard.url(/seed-12.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-12.nimiq.network/i) or
        androguard.url(/seed-13.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-13.nimiq-network.com/i) or
        androguard.url(/seed-13.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-13.nimiq.com/i) or
        androguard.url(/seed-13.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-13.nimiq.network/i) or
        androguard.url(/seed-14.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-14.nimiq-network.com/i) or
        androguard.url(/seed-14.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-14.nimiq.com/i) or
        androguard.url(/seed-14.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-14.nimiq.network/i) or
        androguard.url(/seed-15.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-15.nimiq-network.com/i) or
        androguard.url(/seed-15.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-15.nimiq.com/i) or
        androguard.url(/seed-15.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-15.nimiq.network/i) or
        androguard.url(/seed-16.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-16.nimiq-network.com/i) or
        androguard.url(/seed-16.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-16.nimiq.com/i) or
        androguard.url(/seed-16.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-16.nimiq.network/i) or
        androguard.url(/seed-17.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-17.nimiq-network.com/i) or
        androguard.url(/seed-17.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-17.nimiq.com/i) or
        androguard.url(/seed-17.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-17.nimiq.network/i) or
        androguard.url(/seed-18.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-18.nimiq-network.com/i) or
        androguard.url(/seed-18.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-18.nimiq.com/i) or
        androguard.url(/seed-18.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-18.nimiq.network/i) or
        androguard.url(/seed-19.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-19.nimiq-network.com/i) or
        androguard.url(/seed-19.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-19.nimiq.com/i) or
        androguard.url(/seed-19.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-19.nimiq.network/i) or
        androguard.url(/seed-2.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-2.nimiq-network.com/i) or
        androguard.url(/seed-2.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-2.nimiq.com/i) or
        androguard.url(/seed-2.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-2.nimiq.network/i) or
        androguard.url(/seed-20.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-20.nimiq-network.com/i) or
        androguard.url(/seed-20.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-20.nimiq.com/i) or
        androguard.url(/seed-20.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-20.nimiq.network/i) or
        androguard.url(/seed-3.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-3.nimiq-network.com/i) or
        androguard.url(/seed-3.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-3.nimiq.com/i) or
        androguard.url(/seed-3.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-3.nimiq.network/i) or
        androguard.url(/seed-4.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-4.nimiq-network.com/i) or
        androguard.url(/seed-4.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-4.nimiq.com/i) or
        androguard.url(/seed-4.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-4.nimiq.network/i) or
        androguard.url(/seed-5.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-5.nimiq-network.com/i) or
        androguard.url(/seed-5.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-5.nimiq.com/i) or
        androguard.url(/seed-5.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-5.nimiq.network/i) or
        androguard.url(/seed-6.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-6.nimiq-network.com/i) or
        androguard.url(/seed-6.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-6.nimiq.com/i) or
        androguard.url(/seed-6.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-6.nimiq.network/i) or
        androguard.url(/seed-7.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-7.nimiq-network.com/i) or
        androguard.url(/seed-7.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-7.nimiq.com/i) or
        androguard.url(/seed-7.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-7.nimiq.network/i) or
        androguard.url(/seed-8.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-8.nimiq-network.com/i) or
        androguard.url(/seed-8.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-8.nimiq.com/i) or
        androguard.url(/seed-8.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-8.nimiq.network/i) or
        androguard.url(/seed-9.nimiq-network.com/i) or cuckoo.network.dns_lookup(/seed-9.nimiq-network.com/i) or
        androguard.url(/seed-9.nimiq.com/i) or cuckoo.network.dns_lookup(/seed-9.nimiq.com/i) or
        androguard.url(/seed-9.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-9.nimiq.network/i) or
        androguard.url(/seed-can-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-can-1.inf.nimiq.network/i) or
        androguard.url(/seed-can-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-can-2.inf.nimiq.network/i) or
        androguard.url(/seed-deu-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-deu-1.inf.nimiq.network/i) or
        androguard.url(/seed-deu-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-deu-2.inf.nimiq.network/i) or
        androguard.url(/seed-deu-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-deu-3.inf.nimiq.network/i) or
        androguard.url(/seed-deu-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-deu-4.inf.nimiq.network/i) or
        androguard.url(/seed-fra-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-1.inf.nimiq.network/i) or
        androguard.url(/seed-fra-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-2.inf.nimiq.network/i) or
        androguard.url(/seed-fra-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-3.inf.nimiq.network/i) or
        androguard.url(/seed-fra-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-4.inf.nimiq.network/i) or
        androguard.url(/seed-fra-5.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-5.inf.nimiq.network/i) or
        androguard.url(/seed-fra-6.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-fra-6.inf.nimiq.network/i) or
        androguard.url(/seed-gbr-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-gbr-1.inf.nimiq.network/i) or
        androguard.url(/seed-gbr-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-gbr-2.inf.nimiq.network/i) or
        androguard.url(/seed-gbr-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-gbr-3.inf.nimiq.network/i) or
        androguard.url(/seed-gbr-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-gbr-4.inf.nimiq.network/i) or
        androguard.url(/seed-pol-1.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-pol-1.inf.nimiq.network/i) or
        androguard.url(/seed-pol-2.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-pol-2.inf.nimiq.network/i) or
        androguard.url(/seed-pol-3.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-pol-3.inf.nimiq.network/i) or
        androguard.url(/seed-pol-4.inf.nimiq.network/i) or cuckoo.network.dns_lookup(/seed-pol-4.inf.nimiq.network/i) or
        androguard.url(/seed.nimiqpool.com/i) or cuckoo.network.dns_lookup(/seed.nimiqpool.com/i) or
        androguard.url(/seed1.sushipool.com/i) or cuckoo.network.dns_lookup(/seed1.sushipool.com/i) or
        androguard.url(/shannon.nimiqpool.com/i) or cuckoo.network.dns_lookup(/shannon.nimiqpool.com/i) or
        androguard.url(/sunnimiq.cf/i) or cuckoo.network.dns_lookup(/sunnimiq.cf/i) or
        androguard.url(/sunnimiq1.cf/i) or cuckoo.network.dns_lookup(/sunnimiq1.cf/i) or
        androguard.url(/sunnimiq2.cf/i) or cuckoo.network.dns_lookup(/sunnimiq2.cf/i) or
        androguard.url(/sunnimiq3.cf/i) or cuckoo.network.dns_lookup(/sunnimiq3.cf/i) or
        androguard.url(/sunnimiq4.cf/i) or cuckoo.network.dns_lookup(/sunnimiq4.cf/i) or
        androguard.url(/sunnimiq5.cf/i) or cuckoo.network.dns_lookup(/sunnimiq5.cf/i) or
        androguard.url(/sunnimiq6.cf/i) or cuckoo.network.dns_lookup(/sunnimiq6.cf/i) or
        androguard.url(/tokomaru.nimiqpool.com/i) or cuckoo.network.dns_lookup(/tokomaru.nimiqpool.com/i) or
        androguard.url(/whanganui.nimiqpool.com/i) or cuckoo.network.dns_lookup(/whanganui.nimiqpool.com/i) or
        androguard.url(/www.besocial.online/i) or cuckoo.network.dns_lookup(/www.besocial.online/i) or
        androguard.url(/nimiq.com/i) or cuckoo.network.dns_lookup(/nimiq.com/i) or
        androguard.url(/miner.nimiq.com/i) or cuckoo.network.dns_lookup(/miner.nimiq.com/i) or
        androguard.url(/cdn.nimiq.com/i) or cuckoo.network.dns_lookup(/cdn.nimiq.com/i) or
        androguard.url(/jscoinminer.com/i) or cuckoo.network.dns_lookup(/jscoinminer.com/i) or
        androguard.url(/www.jscoinminer.com/i) or cuckoo.network.dns_lookup(/www.jscoinminer.com/i) or
        androguard.url(/azvjudwr.info/i) or cuckoo.network.dns_lookup(/azvjudwr.info/i) or
        androguard.url(/jroqvbvw.info/i) or cuckoo.network.dns_lookup(/jroqvbvw.info/i) or
        androguard.url(/jyhfuqoh.info/i) or cuckoo.network.dns_lookup(/jyhfuqoh.info/i) or
        androguard.url(/kdowqlpt.info/i) or cuckoo.network.dns_lookup(/kdowqlpt.info/i) or
        androguard.url(/xbasfbno.info/i) or cuckoo.network.dns_lookup(/xbasfbno.info/i) or
        androguard.url(/1beb2a44.space/i) or cuckoo.network.dns_lookup(/1beb2a44.space/i) or
        androguard.url(/300ca0d0.space/i) or cuckoo.network.dns_lookup(/300ca0d0.space/i) or
        androguard.url(/310ca263.space/i) or cuckoo.network.dns_lookup(/310ca263.space/i) or
        androguard.url(/320ca3f6.space/i) or cuckoo.network.dns_lookup(/320ca3f6.space/i) or
        androguard.url(/330ca589.space/i) or cuckoo.network.dns_lookup(/330ca589.space/i) or
        androguard.url(/340ca71c.space/i) or cuckoo.network.dns_lookup(/340ca71c.space/i) or
        androguard.url(/360caa42.space/i) or cuckoo.network.dns_lookup(/360caa42.space/i) or
        androguard.url(/370cabd5.space/i) or cuckoo.network.dns_lookup(/370cabd5.space/i) or
        androguard.url(/3c0cb3b4.space/i) or cuckoo.network.dns_lookup(/3c0cb3b4.space/i) or
        androguard.url(/3d0cb547.space/i) or cuckoo.network.dns_lookup(/3d0cb547.space/i) or
        (any of ($id*)) or
        (any of ($link*)) or
        (any of ($js*)) or 
        (any of ($lib*)) or
        (any of ($api*)) or
        (false)) //just a dummy string	
}
rule koodous_za: official
{
	meta:
		description = "This rule detects the cafebazaar app or link"
	condition:
		androguard.url(/cafebazaar\.ir/)
}
rule Downloader_c
{
    strings:
        $a = "res/mipmap-xxhdpi-v4/ic_launcher_antivirus.pngPK"
		$b = "file:///android_asset"
		$c = "market://"
		$d = "MKKSL/x}^<"
    condition:
        all of them
		}
rule avdobfuscator_b: obfuscator
{
  meta:
    description = "AVDobfuscator (string signatures)"
  strings:
    $s_01 = "_ZNK17ObfuscatedAddressIPFiiiPciS0_S0_EE8originalEv"
    $s_02 = "_ZNK17ObfuscatedAddressIPFiPcEE8originalEv"
    $s_03 = "_ZNK17ObfuscatedAddressIPFvPciEE8originalEv"
    $s_04 = "_ZNK17ObfuscatedAddressIPFvPcS0_EE8originalEv"
    $s_05 = "_ZNK17ObfuscatedAddressIPFvvEE8originalEv"
    $s_06 = "_Z14ObfuscatedCallI17ObfuscatedAddressIPFvvEEJEEvT_DpOT0_"
    $s_07 = "_ZNK17ObfuscatedAddressIPFiPviEE8originalEv"
    $s_08 = "_ZNK17ObfuscatedAddressIPFvPcEE8originalEv"
    $s_09 = "_ZNK17ObfuscatedAddressIPFvP7_JNIEnvEE8originalEv"
    $s_10 = "_ZNK17ObfuscatedAddressIPFvPcS0_iiEE8originalEv"
    $s_11 = "_ZNK17ObfuscatedAddressIPFvcEE8originalEv"
    $s_12 = "_ZNK17ObfuscatedAddressIPFvPviiEE8originalEv"
  condition:
    any of them
}
rule promon_b: packer
{
  meta:
    description = "Promon Shield"
    info        = "https://promon.co/"
    example     = "6a3352f54d9f5199e4bf39687224e58df642d1d91f1d32b069acd4394a0c4fe0"
  strings:
    $a = "libshield.so"
    $b = "deflate"
    $c = "inflateInit2"
    $d = "crc32"
    $s1 = /.ncc/  // Code segment
    $s2 = /.ncd/  // Data segment
    $s3 = /.ncu/  // Another segment
  condition:
    ($a and $b and $c and $d) and
    2 of ($s*)
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
rule Android_MazarBOT_a
{
	meta:
		description = "Rule to detect different variants of MazarBOT"
	strings:
		$sSignature1 = {0A 68 61 72 64 20 72 65 73 65 74 00}
		$sSignature2 = {16 47 65 74 20 76 69 64 65 6F 20 63 6F 64 65 63 20 61 63 63 65 73 73 00}
		$sSignature3 = {2F 44 65 76 41 64 6D 69 6E 44 69 73 61 62 6C 65 72 3B 00}
		$sSignature4 = {0A 4D 79 57 61 6B 65 4C 6F 63 6B 00}
		$sSignature5 = {2F 4F 76 65 72 6C 61 79 56 69 65 77 3B 00}
		$sSignature6 = {2F 52 65 71 75 65 73 74 46 61 63 74 6F 72 79 3B 00}
		$sSignature7 = {14 67 65 74 41 63 74 69 76 65 50 61 63 6B 61 67 65 50 72 65 4C 00}
		$sSignature8 = {0D 68 69 64 65 53 79 73 44 69 61 6C 6F 67 00}
		$sSignature9 = {0F 69 6E 74 65 72 63 65 70 74 20 73 74 61 72 74 00}
		$sSignature10 = {0B 6C 6F 63 6B 20 73 74 61 74 75 73 00}
		$sSignature11 = {13 6D 61 6B 65 49 6E 63 6F 6D 69 6E 67 4D 65 73 73 61 67 65 00}
		$sSignature12 = {14 6D 61 6B 65 49 6E 74 65 72 63 65 70 74 43 6F 6E 66 69 72 6D 00}
		$sSignature13 = {18 72 65 61 64 4D 65 73 73 61 67 65 73 46 72 6F 6D 44 65 76 69 63 65 44 42 00}
	condition:
		4 of them
}
rule package_name_a
{
	meta: 
		author = "https://twitter.com/roskyfrosky"
		description = "This rule detects all banker apps with specific package_names"
	condition:
		androguard.package_name("com.note.donote") or 
		androguard.package_name("cosmetiq.fl") or 
		androguard.package_name("com.glory") or
		androguard.package_name("org.slempo.service") or 
		androguard.package_name("com.construct") or 
		androguard.package_name("com.avito") or
		androguard.package_name("com.wood") or 
		androguard.package_name("ru.drink.lime") or 
		androguard.package_name("com.constre") or  	
		androguard.package_name("com.motion") or
		androguard.package_name("app.six") or
		androguard.package_name("com.example.street.two") or
		androguard.package_name("com.example.livemusay.myapplication")
}
rule rootnik_a: sites
{
	meta:
		description = "sites created as of Feb 2015"
		sample = "17a00e9e8a50a4e2ae0a2a5c88be0769a16c3fc90903dd1cf4f5b0b9b0aa1139"
	condition:
		cuckoo.network.http_request(/http:\/\/applight\.mobi/) and 		cuckoo.network.http_request(/http:\/\/jaxfire\.mobi/)  and cuckoo.network.http_request(/http:\/\/superflashlight\.mobi/) and 		cuckoo.network.http_request(/http:\/\/shenmeapp\.mobi/)
}
rule rootnik2_a: sites2
{
	strings:
	 $a = "aHR0cDovL2Nkbi5hcHBsaWdodC5tb2JpL2FwcGxpZ2h0LzIwMTUvMTQ0MjgyNDQ2MnJlcy5iaW4=" // base 64 encoded: /http:\/\/cdn.applight.mobi\/applight\/2015\/1442824462res.bin/
	condition:
		 cuckoo.network.http_request(/http:\/\/api.jaxfire\.mobi\/app\/getTabsResBin/) and (cuckoo.network.http_request(/http:\/\/cdn.applight.mobi\/applight\/2015\/1442824462res.bin/) or $a)
}
rule rootnik3_a: string
{
	strings:
	$a = "http://api.shenmeapp.info/info/report"
	condition:
	$a or (androguard.url(/applight\.mobi/) and androguard.url(/jaxfire\.mobi/))
}
rule rooting_a {
	meta:
		sample = "7fce9e19534b0a0590c7383c7180b9239af3ad080e0df9d42b0493bb6e0e0ef7" // SHA256
	strings: 
	$a= "http://api01.app001.cn/action/init_dev.php"
$b = "http://api02.app001.cn/action/check_auto_upgrade.php"
$c = "http://api02.app001.cn/action/check_connect.php"
$d = "http://api02.app001.cn/action/check_push.php"
$e = "http://api02.app001.cn/action/get_rooting_app.php"
	condition: 
	$a or $b or $c or $d or $e
}
rule shuanet_c:dropper
{
	meta:
		description = "This rule detects shuanet apps"
		sample = "ee8eb1c47aac2d00aa16dd8eecbae7a7bf415b3a44bc0c299ad0b58bc8e78260"
	strings:
		$a = "/system/app/System_Framework.apk"
		$b = "/system/app/System_Ad.apk"
	condition:
		all of them
}
rule koodous_baa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
	$a = /\cp.{1,} \/system\/app/
	$b = /\cat.{1,} \/system\/app/
	$c = /cp [0-9a-zA-Z] {1,}\/system\/app/
    $d = /cat [0-9a-zA-Z] {1,}\/system\/app/
	condition:
		any of them
}
rule drop_a
{
	meta:
		description = "This rule detects references to other applications"
	strings:
		$a = "Landroid/os/FileObserver"
	condition:
		$a
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
rule apk_inside_b
{
	meta:
		description = "This rule detects an APK file inside META-INF folder, which is not checked by Android system during installation"
		inspiration = "http://blog.trustlook.com/2015/09/09/android-signature-verification-vulnerability-and-exploitation/"
	strings:
		$a = /META-INF\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/
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
rule packers_n
{
	meta:
		description = "Tencent Packer"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_b = "com.tencent.StubShell.ProxyShell"
		$strings_a = "com.tencent.StubShell.ShellHelper"
	condition:
		any of them
}
rule packers_o
{
	meta:
		description = "Tencent Packer"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_b = "com.tencent.StubShell.ProxyShell"
		$strings_a = "com.tencent.StubShell.ShellHelper"
	condition:
		any of them
}
rule packers_p
{
	meta:
		description = "Ijiami Packer"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_b = "rmeabi/libexecmain.so"
		$strings_a = "neo.proxy.DistributeReceiver"
	condition:
		any of them
}
rule packers_q
{
	meta:
		description = "Bangcle Packer"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_b = "assets/bangcleplugin"
		$strings_a = "neo.proxy.DistributeReceiver"
	condition:
		any of them
}
rule packers_r
{
	meta:
		description = "360 Packer"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_b = "libprotectClass"
		$strings_a = "libqupc"
		$strings_c = "com.qihoo.util.StubApplication"
		$strings_d = "com.qihoo.util.DefenceReport"
	condition:
		any of them
}
rule packers_s
{
	meta:
		description = "BaiduPacker"
		thread_level = 3
		in_the_wild = true
	strings:
		$strings_b = "com.baidu.protect.StubApplication"
		$strings_a = "com.baidu.protect.StubProvider"
		$strings_c = "com.baidu.protect.A"
		$strings_d = "baiduprotect.jar"
		$strings_d = "libbaiduprotect"
	condition:
		any of them
}
rule banker_string_a: banker string
{
	meta:
		description = "This family detect your region for subscribe to MMS premium msg. Use ThoughtCrime for WhisperSystems"
		sample = "ea3999c8c9ff732c8df7a261b3b1e0e33510fd9c2ea1e355660224ed8497d8e4"
	strings:
		$string_a = "SmsSecure erkannt"
		$string_b = "ITEM_VIEW_TYPE_FOOTER"
		$string_c = "555&&&555&&&"
		$string_d = "EFIl database di default non verr"
		$string_e = "99registration_activity__your_country_code_and_phone_number"
		$string_f = "Saving attachment to SD card..."
		$string_g = "NUMERO DI TELEFONO"
	condition:
		all of ($string_*)		
}
rule banker_certificate_a: banker certificate
{
	meta:
		description = "This rule detects banker"
		sample = "ea3999c8c9ff732c8df7a261b3b1e0e33510fd9c2ea1e355660224ed8497d8e4"
	condition:
		androguard.certificate.sha1("A7A3310E1335089F985E331523E1DAAB3F319A44") or
		androguard.certificate.sha1("33188A4658EA53F092DC6F9025CFD739E762CBEA") or
		androguard.certificate.sha1("06220B02289A3B44A969E8E5F23F7598D2CE563C") or
		androguard.certificate.sha1("27051D4C951095B6DC3BA59C1F21B9BCEEC02CEF")
}
rule thoughtcrime_a
{
	meta:
		description = "https://github.com/WhisperSystems/Signal-Android/tree/master/src/org/thoughtcrime/securesms"
	condition:
		androguard.permission(/org\.thoughtcrime\.securesms\.ACCESS_SECRETS/) or
		androguard.activity(/org\.thoughtcrime\.securesms\.*/) 
}
rule testing_d
{
	meta:
		description = "WhatsAPP stealer?"
	strings:
	  $b1 = "8d4b155cc9ff81e5cbf6fa7819366a3ec621a656416cd793"
	  $b2 = "1e39f369e90db33aa73b442bbbb6b0b9"
	  $b3 = "346a23652a46392b4d73257c67317e352e3372482177652c"
	condition:
		any of them
}
rule testing_e
{
	meta:
		description = "This rule is a test"
	strings:
	  $b1 = "1xRTT"
	  $b2 = "CDMA"
	  $b3 = "EDGE"
	  $b4 = "eHRPD"
	  $b5 = "EDVO revision 0"
	  $b6 = "EDVO revision A"
	  $b7 = "EDVO revision B"
	  $b8 = "GPRS"
	  $b9 = "HSDPA"
	  $b11 = "HSPA"
	  $b12 = "HSPA+"
	  $b13 = "HSUPA"
	  $b14 = "iDen"
	  $b15 = "LTE"
	  $b16 = "UMTS"
	  $b17 = "CDMA"
	  $b18 = "GSM"
	  $b19 = "SIP"
	condition:
		all of them
}
rule TencentLocation_b: spy
{
	meta:
		description = "This rule detects apps which use Tencent location service, which may be spyware. Also, many apps which use this are suspicious Chinese apps"
	strings:
		$a1 = /addrdesp/i
		$a2 = /resp_json/i
	condition:
		all of ($a*)
}
rule Kemoge_a: Adware Rooter
{
	meta:
		description = "Tries to detect Kemoge adware, based on the C&C url"
	strings:
		$a = /kemoge\.net/
	condition:
		any of them or androguard.url(/kemoge\.net/)
}
rule Agent_Smith_a
{
	strings:
		$a1 = "whatsapp"
    	$a2 = "lenovo.anyshare.gps"
    	$a3 = "mxtech.videoplayer.ad"
    	$a4 = "jio.jioplay.tv"
    	$a5 = "jio.media.jiobeats"
    	$a6 = "jiochat.jiochatapp"
    	$a7 = "jio.join"
    	$a8 = "good.gamecollection"
    	$a9 = "opera.mini.native"
   		$a10 = "startv.hotstar"
    	$a11 = "meitu.beautyplusme"
    	$a12 = "domobile.applock"
    	$a13 = "touchtype.swiftkey"
    	$a14 = "flipkart.android"
    	$a15 = "cn.xender"
    	$a16 = "eterno"
    	$a17 = "truecaller"
	condition:
		all of them
}
rule Clipper_b
{
	meta:
		description = "Tries to detect the Clipper malware"
	strings:
		$a1 = "ClipboardMonitorService"
		$a2 = "ClipboardManager"
		$a3 = "clipboard-history.txt"
	condition:
		all of ($a*)
}
rule koodous_caa: official
{
	meta:
		description = "AgentSmith"
	strings:
		$a = "/api/sdk.ad.requestAds"
		$b = "/api/sdk.ad.requestList"
		$c = "/api/sdk.ad.requestRes"
		$d = "/api/sdk.ad.requestStat"
		$e = "/api/sdk.ad.requestUpdate"
		$f = "/api/sdk.ad.uploadResult"
		$g = "com.infectionapk.patchMain"
		$h = "resa.data.encry"
	condition:
		$a or $b or $c or $d or $d or $e or $f or $g or $h
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
rule PayNimoMandateActivity_a
{
	meta:
		description = "All PayNimo Mandate Activity Tracker"
	condition:
		androguard.activity("com.paynimo.android.payment.DigitalMandateActivity")
}
rule LockerRansomware_a
{
	meta:
		description = "This rule detects apks relatedto the one mentioned on Twitter"
		tweet = "https://twitter.com/virqdroid/status/1144189572068327424"
		sample = "04f15f42b3d44142d8d1b44f95877ab4cdec9ba31d74a40cdea687bd833f142c"
	strings:
		$a1 = "L3N5c3RlbS9iaW4vc2g="
		$a2 = "Conta Gmail"
		$a3 = "Tutorial BTC"
		$a5 = "coockies"
	condition:
		all of ($a*)
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
rule SpywareSpyNote_a
{
	meta:
		description = "Android SpyNote spyware"
		md5 = "22649508c8056351c6ad3a760c39ba39"
	strings:
		$a_1 = "c0c1c3a2c0c1c" fullword
		$a_2 = "e1x1114x61114e" fullword
		$a_3 = "key_logger" fullword
		$a_4 = "Do I have root" fullword
	condition:
		all of ($a_*)
		and
		filesize < 2MB
}
rule VerificationScam_a
{
	meta:
		description = "Android Verification scam"
		md5 = "4e37fe6a140b64a281e2ea08b2c116f0"
	strings:
		$a_2 = "verifycaptcha.com"
		$a_3 = "Mobile Verification required!"
	condition:
		all of ($a_*)
}
rule Samsung_a: Chrysaor
{
	condition:
		androguard.package_name("com.network.android") and		
		file.sha256("ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5") 
}
rule anubis3_a: Dropper
{
	condition:
	  androguard.permission(/READ_EXTERNAL_STORAGE/) and
	  androguard.permission(/RECEIVE_BOOT_COMPLETED/) and
	  androguard.permission(/REQUEST_INSTALL_PACKAGES/) and
	  androguard.permission(/INTERNET/) and
	  androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
	  androguard.permissions_number < 10
}
rule GGTRACK_detecrot_a: trojan
{
	condition:
		androguard.url("http://ggtrack.org/") or
		androguard.url(/ggtrack\.org/) 
}
rule Android_Trojan_SuspiciousPermission_LauncherMiss_a
{
	meta:
		Updated_description = "rules checks the missing launcher"
	strings:
		$a1 = "android.permission.READ_SMS" wide
		$a2 = "android.permission.SEND_SMS" wide
		$a3 = "android.permission.RECEIVE_SMS" wide
		$a4 = "android.permission.WRITE_SMS" wide
		$a5 = "android.permission.READ_CONTACTS" wide
		$a6 = "android.permission.WRITE_CONTACTS" wide
		$b1 = "android.permission.WRITE_EXTERNAL_STORAGE" wide
		$b2 = "android.permission.READ_EXTERNAL_STORAGE" wide
		$b3 = "android.permission.RECEIVE_BOOT_COMPLETED" wide
		$b4 = "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION" wide
		$b5 = "android.permission.SYSTEM_OVERLAY_WINDOW" wide
		$permission = "android.permission." wide
		$exclude = "android.intent.category.LAUNCHER" wide
		$hexstr_targetSdkVersion = {74 00 61 00 72 00 67 00 65 00 74 00 53 00 64 00 6B 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E}
	condition:
		#permission <= 15 and $hexstr_targetSdkVersion and not ($exclude) and 2 of ($a*) and 1 of ($b*)
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
rule Android_HummingBad_a
{
	meta:
		description = "This rule detects Android.HummingBad, trying to root the device"
		sample = "743eb17efb06fa50a8f80b066d162dcd2873b8b94adf79ebf5bed642888a6abd  "
		source = "http://blog.checkpoint.com/2016/02/04/hummingbad-a-persistent-mobile-chain-attack/"
	strings:
		$string_1 = "#!/system/bin/sh\nipm\npm install -r $APKPATH/$APKFILE\necho sucess\n"
		$string_2 = "#!/system/bin/sh\nmount -o rw,remount /system\ncat $APKPATH/$APKFILE > /system/app/$APKFILE\nchmod 0644 /system/app/$APKFILE\npm install -r /system/app/$APKFILE\n\nmount -o ro,remount /system\necho sucess\n"
		$string_3 = "#!/system/bin/sh\n#Power by www.rootzhushou.com\n#Pansing\n\nTEMPPATH=/data/data/$PACKAGE/files\nBUSYBOX=/data/data/$PACKAGE/files/busybox\nexport PATH=$TEMPPATH:$PATH\n\nchmod 777 $TEMPPATH/busybox\nuid=$(busybox id -u)\nif [ $uid -ne 0 ]; then\necho \"Are you root ? OK ,try anyway.\"\nfi\nbusybox mount -o remount,rw /system\nbusybox cat $TEMPPATH/su > /system/xbin/su\nchown 0.0 /system/xbin/su\nchmod 6755 /system/xbin/su\nbusybox cat $TEMPPATH/busybox > /system/xbin/busybox\nchown 0.0 /system/xbin/busybox\nchmod 755 /system/xbin/busybox\necho \"Now, your device is rooted !\"\nsync\n"
		$string_4 = "#!/system/bin/sh\nmount -o rw,remount /system\n/data/data/$PACKAGE/files/busybox mount -o rw,remount /system\n/system/bin/stop nac_server\n/data/data/$PACKAGE/files/busybox rm -r -f /system/xbin/su\n/data/data/$PACKAGE/files/busybox rm -r -f /system/bin/su\n/data/data/$PACKAGE/files/busybox rm -r -f /system/bin/ipm\n/data/data/$PACKAGE/files/busybox rm -r -f /system/xbin/daemonsu\n/data/data/$PACKAGE/files/busybox cat /data/data/$PACKAGE/files/su > /system/bin/su\n/data/data/$PACKAGE/files/busybox cat /data/data/$PACKAGE/files/ipm > /system/bin/ipm\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/bin/su\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/bin/su\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/bin/ipm\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/bin/ipm\n/data/data/$PACKAGE/files/busybox cat /system/bin/su > /system/xbin/su\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/xbin/su\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/xbin/su\n/data/data/$PACKAGE/files/busybox cat /system/xbin/su > /system/xbin/daemonsu\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/xbin/daemonsu\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/xbin/daemonsu\n/data/data/$PACKAGE/files/busybox cat /system/xbin/su > /system/xbin/ku.sud\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/xbin/ku.sud\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/xbin/ku.sud\n/data/data/$PACKAGE/files/busybox cat /data/data/$PACKAGE/files/install-recovery.sh > /system/etc/install-recovery.sh\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/etc/install-recovery.sh\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/etc/install-recovery.sh\n/data/data/$PACKAGE/files/busybox cat /data/data/$PACKAGE/files/99SuperSUDaemon > /system/etc/init.d/99SuperSUDaemon\n/data/data/$PACKAGE/files/busybox chown 0.0 /system/etc/init.d/99SuperSUDaemon\n/data/data/$PACKAGE/files/busybox chmod 6755 /system/etc/init.d/99SuperSUDaemon\n\nmount -o ro,remount /system\n/data/data/$PACKAGE/files/busybox mount -o ro,remount /system\necho \"Now, script finish!\"\n"
		$string_5 = "#!/system/bin/sh\n#Power by www.rootzhushou.com\n#Pansing\n\nTEMPPATH=/data/data/$PACKAGE/files\nBUSYBOX=/data/data/$PACKAGE/files/busybox\nexport PATH=$TEMPPATH:$PATH\n\nchmod 777 $TEMPPATH/busybox\nuid=$(busybox id -u)\nif [ $uid -ne 0 ]; then\necho \"Are you root ? OK ,try anyway.\"\nfi\nmount -o remount,rw /system\n$BUSYBOX mount -o remount,rw /system\nif [ -e \"/system/xbin/su\" -o -L \"/system/xbin/su\" ]; then\necho \"Delete xbin su ...\"\n$BUSYBOX rm -rf /system/xbin/su\nfi\nr\nif [ -e \"/system/bin/su\" -o -L \"/system/bin/su\" ]; then\necho \"Delete bin su ...\"\n$BUSYBOX rm -rf /system/bin/su\nfi\n/system/bin/stop nac_server\n$BUSYBOX cat $TEMPPATH/su > /system/xbin/su\n$BUSYBOX chown 0.0 /system/xbin/su\n$BUSYBOX chmod 6755 /system/xbin/su\n$BUSYBOX cat /system/xbin/su > /system/bin/su\n$BUSYBOX chown 0.0 /system/bin/su\n$BUSYBOX chmod 6755 /system/bin/su\n$BUSYBOX cat $TEMPPATH/busybox > /system/xbin/busybox\n$BUSYBOX chown 0.0 /system/xbin/busybox\n$BUSYBOX chmod 755 /system/xbin/busybox\n\necho \"Now, your device is rooted !\"\nsync\n"
		$string_6 = "http://ppsdk.hmapi.com:10081/ppsdkpost.do"	
	condition:
		$string_1 and $string_2 and $string_3 and $string_4 and $string_5 and $string_6
}
rule Android_HummingBad_b
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
rule marcher_b: official
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
rule smsfraud_d
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
rule smsfraud2_b {
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
rule Dropper_b: official
{
	meta:
		description = "This rule detects a Dropper variant"
		sample = "05f486e38f642f17fbffc5803965a3febefdcffa1a5a6eeedd81a83c835656d4"
	condition:
		androguard.service("com.lx.a.ds") and
		androguard.receiver("com.lx.a.er")
}
rule Banker_g: official
{
	meta:
		description = "This rule detects one variant of Banker malware"
		sample = "0665299A561BC25908BB79DA56077A93C27F1FE05988457DD8E9D342C246DD01"
	strings:
		$a = {67 6F 6F 67 6C 65 2F 73 63 63 2F 41 70 70 4D 61 69 6E}
		$b = {67 65 74 4C 69 6E 65 31 4E 75 6D 62 65 72} // getLine1Number
		$c = {73 65 6E 64 54 65 78 74 4D 65 73 73 61 67 65} // sendTextMessage
	condition:
		$a and $b and $c
}
rule SMSReg_b
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
rule BaDoink_b
{
		meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Virus de la Policia - android"
		sample = "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"
	strings:
		$a = /asem\/[0-9a-zA-Z_\-\.]{0,32}\.apkPK/
	condition:
		$a
}
rule adware_i:aggressive {
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
rule LockeScreen_a
{
	meta:
		description = "https://twitter.com/LukasStefanko/status/687533750838792192"
		sample = "905556a563cfefbc85b4b82532d5e7bb2e01effa25cf8eb23fdbd47d2973ab5b 84cc270c6b6e07e96b34072aff42cd4e01424720abd7c9dfc61e96eb73508112"
	strings:
		$string_a = "lockNow"
		$string_b = "logcat -v threadtime"
		$string_c = "LLogCatBroadcaster"
		$string_d = "force-lock"
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) 
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
rule smsreg_b
{
	meta:
		description = "SMSReg"
		sample = "f861d78cc7a0bb10f4a35268003f8e0af810a888c31483d8896dfd324e7adc39"
	strings:
		$a = {F0 62 98 9E C7 52 A6 26 92 AB C1 31 63}
	condition:
		all of them
}
rule skyhook_a: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
	$b = "http://www.com-09.net"
	$a = "3638730086354773/3927194040"
	$c = "eecbb06a479c4d519669a98494abb5b2"
	$d = "am9objpkb2Ux"
	$e = "53eb59ddb6a0f38e0d000019"
	$f = "fff5c02d3e614bd39d0bc2e8996980ae"
	$g = "59e0bb580dc7bdc0b04cb092961c7ec28b963e74"
	$h = "5FCJZKVGVDRH3PBMFGD9"
	$j = "d4fd7c90-25ad-4bed-b53b-9feb8342217e"
	$k = "e60a9197-f6d2-4d92-90bb-3d5ba7dd84fe"
	$l = "miqkib227014"
	$m = "d637ec136c6b958bcdc5d799251f3b9d"
	condition:
		any of them
}
rule skyhook_b: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
	$a = "_sdka"
	$b = "_sdkab"
	$c = "_sdkzf"
	$d = "_sdkyc"
	condition:
		all of them
}
rule fabric_a: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
	$b = "io.fabric.sdk.android:fabric"
	condition:
		any of them
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
rule clicksummer_b
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
rule ZooParkv1_a
{
	meta:
		description = "This rule detects ZooPark malware version 1"
		sample = ""
	condition:
		androguard.url(/rhubarb2\.com/)
}
rule ZooParkv2_a
{
	meta:
		description = "This rule detects ZooPark malware version 2"
		sample = "041b4d2280cae9720a62350de4541172933909380bb02701a7d20f87e670bac4"
	condition:
		androguard.url(/rhubarb3\.com/)
}
rule Type1_a
{
	meta:
		description = "This rule detects MysteryBot connections"
		sample = "494d0ea7aa98bb2e08d08f26c3e3769e41376d3a6d9dab56b5548f28aebb4397 334f1efd0b347d54a418d1724d51f8451b7d0bebbd05f648383d05c00726a7ae"
	condition:
		androguard.url("http://146.185.234.121/parasite/") or
		androguard.url("http://94.130.0.109/inj.zip") or
		androguard.url("http://89.42.211.24/site/") or
		androguard.url("http://89.42.211.24/sfdsdfsdf/")
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
rule adclicker_a
{
    meta:
        description = "https://www.riskiq.com/blog/interesting-crawls/battery-saving-mobile-scam-app/?utm_source=twitter&utm_medium=social-media&utm_campaign=ad-clicking-scam-app&utm_content=blog"
    condition:
        cuckoo.network.dns_lookup(/aerowizard.me/) or
        cuckoo.network.dns_lookup(/virgintraffic.xyz/) or
        cuckoo.network.dns_lookup(/luxurytraffic.me/) or
        cuckoo.network.dns_lookup(/bosstrack.xyz/) or
        cuckoo.network.dns_lookup(/postbackmylove.xyz/) or
        cuckoo.network.dns_lookup(/releasetraf.xyz/) or
        cuckoo.network.dns_lookup(/yeahguru.me/) or
        cuckoo.network.dns_lookup(/iamtomato.xyz/) or
        cuckoo.network.dns_lookup(/knossos.xyz/) or
        cuckoo.network.dns_lookup(/mediapostback.xyz/) or
        cuckoo.network.dns_lookup(/conversioncap.xyz/) or
        cuckoo.network.dns_lookup(/exo-click.xyz/) or
        cuckoo.network.dns_lookup(/trafficreach.xyz/) or
        cuckoo.network.dns_lookup(/trackthisurl.xyz/) or
        cuckoo.network.dns_lookup(/visitidtrk.xyz/) or
        cuckoo.network.dns_lookup(/focusrates.xyz/) or
        cuckoo.network.dns_lookup(/shopgroup.xyz/) or
        cuckoo.network.dns_lookup(/cashplugin.xyz/) or
        cuckoo.network.dns_lookup(/secretdroid.xyz/) or
        cuckoo.network.dns_lookup(/newyearpage.xyz/) or
        cuckoo.network.dns_lookup(/moneroxmr.xyz/) or
        cuckoo.network.dns_lookup(/moonleaders.me/) or
        cuckoo.network.dns_lookup(/rocketdrive.me/) or
        cuckoo.network.dns_lookup(/callthepiggy.xyz/) or
		cuckoo.network.dns_lookup(/109.169.85.117/) or
		cuckoo.network.dns_lookup(/109.169.85.119/) or
		cuckoo.network.dns_lookup(/109.169.87.58/)
}
rule Trojan_j: BankBot
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
rule Trojan_2_d: BankBot
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
rule Trojan_3_d: BankBot
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
rule Trojan_4_d: BankBot
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
rule Android_OverSeer_a
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-August-2016"
		description = "This rule try to detect OverSeer."
		references = "https://blog.lookout.com/embassy-spyware-google-play"
	condition:
		androguard.receiver(/test\.parse\.AlarmReceiver/i) and
		androguard.receiver(/test\.parse\.SenderReceiver/i) and
		androguard.receiver(/test\.parse\.NetworkReceiver/i) and
		androguard.filter(/dex\.SEND_ACTION/i)
}
rule MysteryBot_a
{
	meta:
		description = "This rule will be able to tag all MysteryBot samples"
		refernces = "https://www.threatfabric.com/blogs/mysterybot__a_new_android_banking_trojan_ready_for_android_7_and_8.html"
		hash_1 = "a282dc3206efa5e1c3ecfb809dcb1abaf434b8cc006bcadcd0add157beafa864"
		hash_2 = "334f1efd0b347d54a418d1724d51f8451b7d0bebbd05f648383d05c00726a7ae"
		hash_3 = "62a09c4994f11ffd61b7be99dd0ff1c64097c4ca5806c5eca73c57cb3a1bc36a"
		author = "Jacob Soo Lead Re"
		date = "17-June-2018"
	condition:
		androguard.service(/CommandService/i)
		and androguard.receiver(/Cripts/i) 
		and androguard.receiver(/Scrynlock/i) 
		and androguard.permission(/android\.permission\.BIND_DEVICE_ADMIN/i)
		and androguard.permission(/PACKAGE_USAGE_STATS/i)
		and androguard.filter(/android\.app\.action\.DEVICE_ADMIN_DISABLED/i) 
}
rule koodous_daa: official
{
	strings:
		$ = "whb"
		$="com.epost.psf.sdsi"
		$="com.hanabank.ebk.channel.android.hananbank"
		$="com.ibk.neobanking"
		$="com.kbstar.kbbank"
		$="com.kftc.kjbsmb"
		$="com.ncsoft.lineagem"
		$="com.sc.danb.scbankapp"
		$="com.shinhan.sbanking"
		$="com.smg.spbs"
		$="nh.smart"
		$="com.atsolution.android.uotp2"
		$="com.ncsoft.lineagem19"
		$="com.nexon.axe"
		$="com.nexon.nxplay"
		$="com.webzen.muorigin.google"
		$="com.wooribank.pib.smart"
		$="kr.co.happymoney.android.happymoney"
		$="kr.co.neople.neopleotp"
		$="https://www.baidu.com/p/%s/detail"
	condition:
		any of them
}
rule POB_1_b
{
	meta:
		description = "Detects few POB apps"
	condition:
		(androguard.receiver(/android\.app\.admin\.DeviceAdminReceiver/) and
		 androguard.service(/pob\.xyz\.WS/))
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
rule SMSFraude_a
{
	meta:
		autor = "sadfud"
		description = "Se conecta a un panel desde el que descarga e instala nuevas aplicaciones"
	condition:
		androguard.url(/app\.yx93\.com/)		
}
rule zitmo_test_a
{
	meta:
		description = "Zitmo"
		samples = "be90c12ea4a9dc40557a492015164eae57002de55387c7d631324ae396f7343c"
	strings:
		$a = "ACTION_SHUTDOWN"
		$b = "BOOT_COMPLETED"
		$c = "REBOOT"
		$d = "USER_PRESENT"
		$e = "SMS_RECEIVED"
		$f = "erfolgreich"
	condition:
	    all of them and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.RECEIVE_SMS/)
}
rule VikingMalware_a
{
	meta:
		description = "Viking like malware"
	strings:
		$a = "reportreward10.info:8830"
	condition:
		$a or
		androguard.url(/reportreward10\.info/) or
		cuckoo.network.dns_lookup(/185\.159\.81\.155/)
}
rule koodous_eaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.url(/umeng\.info/) or
		cuckoo.network.dns_lookup(/umeng.info/) or
		cuckoo.network.http_request(/45.77.25.109/)	
}
rule ransomware_h
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
rule Chineseporn_3_a
{
	meta:
		description = "Detects few Chinese Porn apps"
	condition:
		(androguard.receiver(/lx\.Asver/) and
		 androguard.receiver(/lx\.Csver/))
}
rule koodous_faa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = "06741d050adeb395"
		$b = "351451208401216"
		$c = "00:26:37:17:3C:71"
	condition:
		any of them
}
rule allatori_a: obfuscator
{
  meta:
    description = "Allatori (likely)"
  strings:
    $s = "ALLATORI" nocase
	$demo = "ALLATORIxDEMO"
  condition:
    $s and not $demo
}
rule allatori_demo_b: obfuscator
{
  meta:
    description = "Allatori demo"
  strings:
    $s = "ALLATORIxDEMO"
  condition:
    $s
}
rule Android_Triada_c: android
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
rule koodous_gaa: official
{
	meta:
		description = "remount system"
	strings:
		$a = "mount -o remount rw /system"
	condition:
		$a
}
rule apkpacker_a: packer
{
    meta:
        description = "ApkPacker"
    strings:
        $a = "assets/ApkPacker/apkPackerConfiguration"
        $b = "assets/ApkPacker/classes.dex"
    condition:
        all of them
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
rule dexprotector_new_a: packer
{
  meta:
    description = "DexProtector"
 strings:
    $encrptlib_1 = /assets\/[A-Za-z0-9.]{2,50}\.arm\-v7\.so\.dat/
    $encrptlib_2 = /assets\/[A-Za-z0-9.]{2,50}\.arm\-v8\.so\.dat/
    $encrptlib_3 = /assets\/[A-Za-z0-9.]{2,50}\.arm\.so\.dat/
    $encrptlib_4 = /assets\/[A-Za-z0-9.]{2,50}\.dex\.dat/
    $encrptlib_5 = /assets\/[A-Za-z0-9.]{2,50}\.x86\.so\.dat/
    $encrptlib_6 = /assets\/[A-Za-z0-9.]{2,50}\.x86\_64\.so\.dat/
    $encrptcustom = /assets\/[A-Za-z0-9.]{2,50}\.mp3/
	$a_1 = "assets/dp.arm.so.dat"
    $a_2 = "assets/dp.arm-v7.so.dat"
    $a_3 = "assets/dp.arm-v8.so.dat"
    $a_4 = "assets/dp.x86.so.dat"
    $a_5 = "assets/dp.mp3"
  condition:
    2 of ($encrptlib_*) and $encrptcustom and
	not any of ($a_*)
}
rule odd_behaviours_a
{
	meta:
		authors = "Igor and Elize"
		date = "13 November"
		description = "This rule detects odd behaviours"
	strings: 
		$a = "android.intent.action.NEW_OUTGOING_CALL"
		$b = "config.cloudzad.com"
	condition:
		($a or $b)
}
rule koodous_haa: official
{
	meta:
		description = "This rule detects DroidKhungFu1 like applications"
	strings:
	$a1 = "onCreate.java"
	$a2 = "updateInfo.java"
	$a3 = "cpLegacyRes.java"
	$a4 = "decrypt.java"
	$a5 = "doExecuteTask.java"
	$a6 = "DeleteApp.java"
	condition:
		androguard.service(".google.ssearch") and
		all of ($a*)
}
rule flipcat_a
{
	meta:
		description = "This ruleset detects apps that could be malicious as ru.flipcat.niceplace"
	condition:
		androguard.url("https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg") and
		androguard.url("http://vignette2.wikia.nocookie.net/logopedia/images/d/d2/Google_icon_2015.png") or
		androguard.activity("org.mightyfrog.android.simplenotepad.NoteEditor") or 
		androguard.activity("com.oneminorder.pizzagirl.sdk.activity.StartActivity") and
		androguard.permission(/android.permission.BLUETOOTH/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
}
rule CryptoLocker_a: SimpLocker
{
    meta:
        description = "Ruleset that detects the SimpLocker application"
        reference = "http://kharon.gforge.inria.fr/dataset/malware_SimpLocker.html"
    strings:
        $string_1 = "TorSender" // Function title of Tor-proxying class
        $string_2 = "AesCrypt" // Function title to Encrypt files
        $string_3 = "PAYSAFECARD_DIGITS_NUMBER" // Payment method information
    condition:
        all of them
}
rule Trojan_k: SmsBoxer
{
    meta:
        description = "Trojan abusing pay-per-SMS services"
        source = "26c69c790a8d651f797c36e6183b5d56b02bf211d58ad3f69888f40029154bed"
    strings:
        $string_1 = "http://androgamer.ru/engine/download.php?id=363" nocase
        $string_2 = "2438+1305299+x+a" nocase
    condition:
        all of ($string_*)
        and (
            androguard.permission(/android.permission.RECEIVE_SMS/) 
            or androguard.permission(/android.permission.READ_SMS/)
        )
}
rule SaveMe_b
{
	meta:
		description = "This rule detects APK's similar to SaveMe"
	strings:
		$a = "android.intent.action.CALL"
		$b = "content://call_log/calls"
	condition:
		androguard.permission(/android.permission.SEND_SMS/) and
		$a and
		$b
}
rule Similar_to_Facebook_Free_Basics_a
{
	meta:
		description = "This rule detects APK's with the same permissions as the Facebook (Free Basics) APK"
	condition:
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_SMS/) and
		androguard.permission(/android.permission.RECIEVE_SMS/)	
}
rule AndroidKungFu1_a
{
	meta:
		description = "This rule detects DroidKungFu1."
		sample = "881ee009e90d7d70d2802c3193190d973445d807"
		reference = "http://kharon.gforge.inria.fr/dataset/malware_DroidKungFu1.html"
	condition:
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.REQUEST_INSTALL_PACKAGES/)
}
rule Hack_game_candy_a
{
    meta:
        package_name = "com.hdc.bookmark189248"
		Author = "Lorensius W. L. T"
        email = "lorenz@londatiga.net"
        sample = "6ad5fa4ce0c0d92540c89580868da133"
    strings:
        $a = "http://mobileapp.url.ph"
        $b = "com.hdc.bookmark189248.MainActivity"
		$c = "com.hdc.bookmark189248.WebActivity"
		$d = "android.intent.category.LAUNCHER"
		$e = "android.intent.action.MAIN"
    condition:
        all of them
}
rule koodous_iaa: official
{
	meta:
		description = "This rule detects a variation of Google Chrome lookalikes"
		sample = "786544eff4d873427827ccecbf96e3341da09b94a20c1b0a5a29ed47921b83d4"
	condition:
		androguard.package_name("gayk.hqcwj.ndsec") and
		androguard.app_name("Chrome") and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		androguard.certificate.sha1("13586b6fe4f5d4c16e17d8b1b6c43883708125e3") and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
}
rule SaveMeProtection_a
{
meta: 
description = "Protect against the harmful SaveMe application"
strings: 
	$a = "http://xxxxmarketing.com"
	$b = "GTSTSR.EXT_SMS"
condition:
	($a and $b)
}
rule koodous_jaa: official
{
	meta:
		description = "This rule detects simplock application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$a = {63 6F 6D 24 6B 6F 6F 64 6F 75 73 24 61 6E 64 72 6F 69 64}
	condition:
		androguard.package_name("com.koodous.android") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.RECEIVED_BOOT_COMPLETED/) and
		androguard.permission(/android.permission.WAKE_LOCK/) and
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.certificate.sha1("8399A145C14393A55AC4FCEEFB7AB4522A905139") and
		androguard.url(/koodous\.com/) and
		$a and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
}
rule billiards_a
{
	meta:
		description = "Prevents the creation of network sockets and linking to dangerous files"  
	strings:
		$a = "android.permission.INTERNET"
        $b = "graphs.facebook.com"
	condition:
            ($a or $b)
}
rule Banks_Strings_bbva_a {
	strings:
		$string_1 = /bbva\.es/
		$string_2 = /bbvanetcash\.com/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_scotiabank_a {
	strings:
		$string_1 = /scotiabank\.com/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_bancosantander_a {
	strings:
		$string_1 = /bancosantander\.es/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_bankia_a {
	strings:
		$string_1 = /bankia\.es/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_lacaixa_a {
	strings:
		$string_1 = /lacaixa\.es/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_bancsabadell_a {
	strings:
		$string_1 = /bancsabadell\.com/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_banamex_a {
	strings:
		$string_1 = /banamex\.com/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_caixabank_a {
	strings:
		$string_1 = /caixabank\.es/
	condition:
		1 of ($string_*)
}
rule Banks_Strings_citibank_a {
	strings:
		$string_1 = /citibank\.com/
	condition:
		1 of ($string_*)
}
rule bicho_a {
	strings:
		$string_1 = /CREATE TABLE IF NOT EXISTS raw_events/
		$string_2 = /com\.google\.firebase\.provider\.FirebaseInitProvider/
	condition:
		1 of ($string_*) and
		androguard.permission(/android.permission.READ_SMS/) and 
		androguard.permission(/android.permission.CAMERA/) and 
		androguard.permission(/com.google.android.c2dm.permission.RECEIVE/) and 
		androguard.permission(/android.permission.INTERNET/) and 
		androguard.permission(/android.permission.ACCESS_NETWORK_STATE/)
}
rule RedAlert2_a: Banker
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$exec_0 = "/system/bin/toolbox ps -p - P -x -c"
		$str_10_0 = "LAUNCH_APP"
		$str_10_1 = "launchApp"
		$str_12_0 = "SEND_USSD"
		$str_12_1 = "sendUssd"
		$res_0 = "146.0.72.85:7878"
		$res_1 = "146.0.72.85"
		$res_2 = "url_dcsiv4t"
		$res_3 = "url_dhfcyseu437"
		$res_4 = "twitter response is NOT OK!"
		$res_5 = "tweet-text"
		$str_5_0 = "RESET_DEFAULT_SMS"
		$str_5_1 = "resetDefaultSms"
		$str_4_0 = "SET_DEFAULT_SMS"
		$str_4_1 = "setDefaultSms"
		$str_7_0 = "GET_CALL_LIST"
		$str_7_1 = "getCallList"
		$str_6_0 = "GET_SMS_LIST"
		$str_6_1 = "getSmsList"
		$str_1_0 = "START_SMS_INTERCEPTION"
		$str_1_1 = "startSmsInterception"
		$str_3_0 = "SEND_SMS"
		$str_3_1 = "sendSms"
		$str_2_0 = "STOP_SMS_INTERCEPTION"
		$str_2_1 = "stopSmsInterception"
		$str_9_0 = "SET_ADMIN"
		$str_9_1 = "setAdmin"
		$str_8_0 = "GET_CONTACT_LIST"
		$str_8_1 = "getContactList"
	condition:
		any of ($res_*) or
		all of ($exec_*) or
		all of ($str_10_*) or
		all of ($str_12_*) or
		all of ($str_5_*) or
		all of ($str_4_*) or
		all of ($str_7_*) or
		all of ($str_6_*) or
		all of ($str_1_*) or
		all of ($str_3_*) or
		all of ($str_2_*) or
		all of ($str_9_*) or
		all of ($str_8_*)
}
rule readsms_a
{
	meta:
		description = "This rule detects read_sms"
	condition:
		androguard.permission(/android.permission.READ_SMS/)
}
rule storage_b
{
	meta:
		description = "This rule detects READ_EXTERNAL_STORAGE"
	condition:
		androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/)
}
rule Malicious_certificate_a
{
	meta:
		description = "This rule detects Mazarbot samples for Raiffeisen bank"
		samples = "5c5f7f9e07b1e1c67a55ce56a78f717d"
	condition:
		androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB")
}
rule sorter_b: official
{
	condition:
		cuckoo.network.dns_lookup(/ds.dd.15/) or
		cuckoo.network.dns_lookup(/is.ca.15/) or
		cuckoo.network.dns_lookup(/q1.zxl/) or 
		cuckoo.network.dns_lookup(/sdk.vacuu/) or
		cuckoo.network.dns_lookup(/www.tb/) or
		cuckoo.network.dns_lookup(/www.vu/)
}
rule koodous_kaa: official
{
	meta:
		description = "This rule detects mazain application, used to show all Yara rules 						potential"
    strings:
        $str_1 = "com.bbva.bbvacontigo"
		$str_2 = "com.bbva.bbvawalletmx"
		$str_3 = "com.bbva.netcash"
    condition:
        all of ($str_*)
}
rule HummingWhale_c
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
rule approov_d
{
	meta:
        description = "Approov library"
	strings:
		$approov = "approov" nocase
	condition:
		any of them
}
rule koodous_laa: BTC_ETH_addr_detection
{
	meta:
		description = "This rule detects bitcoin and ethereum addresses"
	strings:
		$a = "/^(0x)?[0-9a-fA-F]{40}$/"
		$b = "/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/"
	condition:
		$a or $b		
}
rule packers_t: NS
{
	meta:
		description = "find NS apks"
	strings:
		$launcher = "com.tns.NativeScriptActivity"
	condition:
		$launcher
}
rule koodous_maa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	condition:
		androguard.package_name("com.byl.sms")
}
rule FakeGoogleUpdate_a
{
	meta:
		description = "Detects Fake Google Update Apps"
	condition:
		androguard.app_name("Google Update") 
}
rule AdwareRule_a: Adware {
	meta:
		description = "Detects Adware Apps"
	condition:
		androguard.package_name("com.chownow.manafoodbar") 
		or
		androguard.package_name("xyz.fiestaapps.burnbellyfat") 
		or
		androguard.package_name("com.app.stoneoven") 
		or
		androguard.package_name("com.ResepPempek.rizaluye") 
		or
		androguard.package_name("tdd.tdd.tdd") 
		or
		androguard.package_name("com.paytronicapp.admin.pizzafactory") 
		}
rule anjian_1_a: jinling
{
	meta:
		description = "anjianjianling"
		sample = "ce84bbd4359a621084f405635c4eb7853b7af8647e819a6d4b4b40db81511e92"
	strings:
		$a = "assets/script.lc" //rule_1
		$b = "mobileanjian.com" 
	condition:
		$a or $b
}
rule xposed_1_a: xposed
{
	meta:
		description = "xposed"
		sample = "25093f6d4e9e73ecf9c83f635722ea84117f56b6a673a72d0bc6529b24768553"
	strings:
		$a = "assets/xposed_init" //rule_1
	condition:
		$a
}
rule autojs_1_a: autojs
{
	meta:
		description = "aujojs"
		sample = "ca39abfbca6f508329434186cf38d35e37bf5c0999eb39d1ad08f21a6b059ca9"
	strings:
		$a = "assets/project/main.js" //rule_1
		$b = "assets/project/project.json"
	condition:
		$a or $b
}
rule mainjsd_1_a: mainjsd
{
	meta:
		description = "manjsd"
		sample = "7f23e272f5e946bd3bae08debe9fef0e980913d6cc0a5b6a8efcd5d756c7b750"
	strings:
		$a = "assets/main.jsd" //rule_1
	condition:
		$a
}
rule koodous_naa: official
 {
     meta:
         description = "This rule detects the koodous application, used to show all Yara rules potential"
         sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
     strings:
     $a = /Created\-By\: DexGuard\, version.+/
     condition:
         all of them
         
 }
rule koodous_oaa: official
 {
     meta:
         description = "Dexguard Detect in assets"
         sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
     strings:
     $a = /Created\-By\: DexGuard\, version.+
     condition:
         all of them
         
 }
rule koodous_paa: official
{
	meta:
		description = "This rule detects the instagram apps suspicious to password stealing"
		sample = "7ec580e72b93eb9c5f858890e979f2fe10210d40adc522f93faa7c46cd0958b0"
	strings:
		$instagram = "https://www.instagram.com/accounts/login"
		$password = "'password'"
		$addJavaScript = "addJavascriptInterface"
	condition:
		$instagram and
		$password and
		$addJavaScript
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
rule Miners_cpuminer_b: coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
	strings:
		$a1 = "MinerSDKRunnable"
		$a2 = "startMiner"
		$a3 = "stop_miner"
		$a4 = "cpuminer_start"
	condition:
		any of them
}
rule Miners_lib_b: coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
	strings:
		$a1 = "libcpuminer.so"
		$a2 = "libcpuminerpie.so"
	condition:
		$a1 or $a2
}
rule Androidos_js_b: coinminer
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/coin-miner-mobile-malware-returns-hits-google-play/; 		https://twitter.com/LukasStefanko/status/925010737608712195"
		sample = "22581e7e76a09d404d093ab755888743b4c908518c47af66225e2da991d112f0"
		author = "https://koodous.com/analysts/pr3w"
	strings:
		$url = "coinhive.com/lib/coinhive.min.js"
		$s1 = "CoinHive.User"
		$s2 = "CoinHive.Anonymous"
	condition:
		$url and 1 of ($s*)	
}
rule Miner_a_b: coinminer
{
	meta:
		    description = "Coinhive"
			author = "https://koodous.com/analysts/JJRLR"
	strings:
	    $miner = "https://coinhive.com/lib/coinhive.min.js" nocase
	    $miner1 = "https://coin-hive.com/lib/coinhive.min.js" nocase
	    $miner2 = "new.CoinHive.Anonymous" nocase
	    $miner3 = "https://security.fblaster.com" nocase
	    $miner4 = "https://wwww.cryptonoter.com/processor.js" nocase
	    $miner5 = "https://jsecoin.com/server/api/" nocase
	    $miner6 = "https://digxmr.com/deepMiner.js" nocase
	    $miner7 = "https://www.freecontent.bid/FaSb.js" nocase
		$miner8 = "htps://authedmine.com/lib/authedmine.min.js" nocase
	    $miner9 = "https://www.bitcoinplus.com/js/miner.js" nocase
	    $miner10 = "https://www.monkeyminer.net" nocase
	condition:
	    any of them
}
rule miner_adb_b
{
	meta:
		description = "This rule detects adb miner "
		sample = "412874e10fe6d7295ad7eb210da352a1"
		author = "https://koodous.com/analysts/skeptre"
	strings:
		$a_1 = "/data/local/tmp/droidbot"
		$aa_1 = "pool.monero.hashvault.pro:5555"
		$aa_2 = "pool.minexmr.com:7777"
	condition:
		$a_1 and 
		any of ($aa_*)
}
rule miner_b_b: coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
	strings:
		$a1 = "android-cpuminer/"
		$a2 = "mining.subscribe"
		$url1 = "https://coinhive.com/lib/coinhive.min.js" nocase
		$url2 = "https://coin-hive.com/lib/coinhive.min.js" nocase
		$url3 = "https://crypto-loot.com/lib/miner.min.js" nocase
		$url4 = "https://camillesanz.com/lib/status.js" nocase
		$url5 = "https://www.coinblind.com/lib/coinblind_beta.js" nocase
		$url6 = "http://jquerystatistics.org/update.js" nocase
		$url7 = "http://www.etacontent.com/js/mone.min.js" nocase
		$url8 = "https://cazala.github.io/coin-hive-proxy/client.js" nocase
		$url9 = "http://eruuludam.mn/web/coinhive.min.js" nocase
		$url10 = "http://www.playerhd2.pw/js/adsensebase.js" nocase
	condition:
		$a1 or $a2 or 1 of ($url*)	
}
rule miner_b_c: coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
	strings:
		$a1 = "android-cpuminer/"
		$a2 = "mining.subscribe"
		$url1 = "https://coinhive.com/lib/coinhive.min.js" nocase
		$url2 = "https://coin-hive.com/lib/coinhive.min.js" nocase
		$url3 = "https://crypto-loot.com/lib/miner.min.js" nocase
		$url4 = "https://camillesanz.com/lib/status.js" nocase
		$url5 = "https://www.coinblind.com/lib/coinblind_beta.js" nocase
		$url6 = "http://jquerystatistics.org/update.js" nocase
		$url7 = "http://www.etacontent.com/js/mone.min.js" nocase
		$url8 = "https://cazala.github.io/coin-hive-proxy/client.js" nocase
		$url9 = "http://eruuludam.mn/web/coinhive.min.js" nocase
		$url10 = "http://www.playerhd2.pw/js/adsensebase.js" nocase
	condition:
		$a1 or $a2 or 1 of ($url*)	
}
rule miner_adb_c
{
	meta:
		description = "This rule detects adb miner "
		sample = "412874e10fe6d7295ad7eb210da352a1"
		author = "https://koodous.com/analysts/skeptre"
	strings:
		$a_1 = "/data/local/tmp/droidbot"
		$aa_1 = "pool.monero.hashvault.pro:5555"
		$aa_2 = "pool.minexmr.com:7777"
	condition:
		$a_1 and 
		any of ($aa_*)
}
rule Miner_a_c: coinminer
{
	meta:
		    description = "Coinhive"
			author = "https://koodous.com/analysts/JJRLR"
	strings:
	    $miner = "https://coinhive.com/lib/coinhive.min.js" nocase
	    $miner1 = "https://coin-hive.com/lib/coinhive.min.js" nocase
	    $miner2 = "new.CoinHive.Anonymous" nocase
	    $miner3 = "https://security.fblaster.com" nocase
	    $miner4 = "https://wwww.cryptonoter.com/processor.js" nocase
	    $miner5 = "https://jsecoin.com/server/api/" nocase
	    $miner6 = "https://digxmr.com/deepMiner.js" nocase
	    $miner7 = "https://www.freecontent.bid/FaSb.js" nocase
		$miner8 = "htps://authedmine.com/lib/authedmine.min.js" nocase
	    $miner9 = "https://www.bitcoinplus.com/js/miner.js" nocase
	    $miner10 = "https://www.monkeyminer.net" nocase
	condition:
	    any of them
}
rule Androidos_js_c: coinminer
{
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/coin-miner-mobile-malware-returns-hits-google-play/; 		https://twitter.com/LukasStefanko/status/925010737608712195"
		sample = "22581e7e76a09d404d093ab755888743b4c908518c47af66225e2da991d112f0"
		author = "https://koodous.com/analysts/pr3w"
	strings:
		$url = "coinhive.com/lib/coinhive.min.js"
		$s1 = "CoinHive.User"
		$s2 = "CoinHive.Anonymous"
	condition:
		$url and 1 of ($s*)	
}
rule Miners_lib_c: coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
	strings:
		$a1 = "libcpuminer.so"
		$a2 = "libcpuminerpie.so"
	condition:
		$a1 or $a2
}
rule Miners_cpuminer_c: coinminer
{
	meta:
		description = "This rule detects suspicious APK miners"
		author = "mmorenog"
	strings:
		$a1 = "MinerSDKRunnable"
		$a2 = "startMiner"
		$a3 = "stop_miner"
		$a4 = "cpuminer_start"
	condition:
		any of them
}
rule Fornite_a: fake
{
	meta:
		description = "This rule detects Fortnite Fake APKs"
		sample = ""
	condition:
		(androguard.package_name("com.epicgames.portal") or androguard.app_name("Fortnite")) and not
		androguard.certificate.sha1("707566F8B09B4C8BFD772E1B536D581F19BC3012")
}
rule PayTMActivity_b
{
	meta:
		description = "All PayTM SDK Apps"	
	condition:
		androguard.activity("com.paytm.pgsdk.PaytmPGActivity")		
}
rule potential_miners_by_url_a: miner
{
	meta:
		description = "This rule detects potential miners using urls"
		author = "https://koodous.com/analysts/zyrik"
	strings:
        $url1 = "coinhive.com"
        $url2 = "authedmine.com"
        $url3 = "minercry.pt"
        $url4 = "nfwebminer.com"
        $url5 = "load.jsecoin.com"
        $url6 = "webmine.cz"
        $url7 = "webmine.pro"
        $url8 = "www.coinimp.com"
        $url9 = "freecontent.stream"
        $url10 = "freecontent.data"
        $url11 = "freecontent.date"
        $url12 = "apin.monerise.com"
        $url13 = "minescripts.info"
        $url14 = "snipli.com"
        $url15 = "abc.pema.cl"
        $url16 = "metrika.ron.si"
        $url17 = "hallaert.online"
        $url18 = "st.kjli.fi "
        $url19 = "minr.pw"
        $url20 = "mepirtedic.com"
        $url21 = "weline.info"
        $url22 = "datasecu.download"
        $url23 = "cloudflane.com"
        $url24 = "hemnes.win"
        $url25 = "rand.com.ru"
        $url26 = "count.im"
        $url27 = "coinpot.co"
        $url28 = "gnrdomimplementation.com"
        $url29 = "metamedia.host"
        $url30 = "1q2w3.website"
        $url31 = "whysoserius.club"
        $url32 = "adless.io"
        $url33 = "moneromining.online"
        $url34 = "afminer.com"
        $url35 = "ajplugins.com"
        $url36 = "anisearch.ru"
        $url37 = "ulnawoyyzbljc.ru"
        $url38 = "mining.best"
        $url39 = "webxmr.com"
        $url40 = "cortacoin.com"
        $url41 = "jsminer.net"
        $url42 = "coinhive.min.js"
        $url43 = "load.jsecoin.com"
        $url44 = "minr.pw"
        $url45 = "st.kjli.fi"
        $url46 = "metrika.ron.si"
        $url47 = "cdn.rove.cl"
        $url48 = "host.d-ns.ga"
        $url49 = "static.hk.rs"
        $url50 = "hallaert.online"
        $url51 = "cnt.statistic.date"
        $url52 = "cdn.static-cnt.bid"
        $url53 = "coinimp.com"
        $url54 = "hashing.win"
        $url55 = "projectpoi.min"
        $url56 = "afminer.com"
        $url57 = "papoto.com"
        $url58 = "papoto.js"
        $url59 = "miner.php"
	condition:
		androguard.permission(/android.permission.INTERNET/) and 
		(any of them)
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
rule redalert_b {
	strings:
		$string_1 = /http:\/\/\S+:7878/
		$string_2 = ">sban</string>"
		$string_3 = ">gt</string>"
	condition:
		1 of ($string_*)
}
rule Fake_video_apps_a
{
	meta:
		description = "Detects few Video Player apps"
	strings:
		$a_1 = "am/xtrack/StereoReceiver"
		$a_2 = "am/xtrack/LolaActivity"
		$b_1 = "http://ccthi.enconfhz.com"
 		$b_2 = "http://first.luckshery.com"
		$b_3 = "http://cthi.nconfhz.com"
		$b_4 = "http://three.nameapp.xyz"
		$b_5 = "http://api.jetbudjet.in"
		$b_6 = "http://api.mobengine.xyz"
		$b_7 = "http://con.rsconf.site"
		$b_8 = "http://one.nameapp.xyz"
		$b_9 = "http://get.confhz.space"
		$b_10 = "http://mi1k.io"
	condition:
		all of ($a_*) and 
 		any of ($b_*)	
}
rule koodous_qaa: official
{
	meta:
		description = "hamrahpay.com"
	condition:
		androguard.url(/hamrahpay\.com/)
}
rule koodous_raa: official
{
	meta:
		description = "adad - network"
	condition:
		androguard.activity(/ir.adad/i) or
		androguard.url(/s\.adad\.ir/)
}
rule koodous_saa: official
{
	meta:
		description = "harsobh mirror"
	condition:
		androguard.url(/mirror1\.harsobh\.com/)
}
rule koodous_taa: official
{
	meta:
		description = "ronash - pushe"
	condition:
		androguard.activity(/ronash/i) or
		androguard.url(/ronash\.co/)
}
rule koodous_uaa: official
{
	meta:
		description = "Cheshmak Network"
	condition:
		androguard.package_name("me.cheshmak.android.sdk.core") or
		androguard.url(/sdk\.cheshmak\.me/) or
		androguard.url(/cheshmak\.me/) or
		androguard.url(/123\.cheshmak\.me/)
}
rule Trojan_l: BankBot
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
rule Trojan_2_e: BankBot
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
rule Trojan_3_e: BankBot
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
rule Trojan_4_e: BankBot
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
private global rule no_FPs
{
	condition:
		not androguard.certificate.sha1("9CA5170F381919DFE0446FCDAB18B19A143B3163")
}
rule coudw_b: amtrckr
{
	meta:
		family = "coudw"
	condition:
		androguard.url(/s\.cloudsota\.com/)
}
rule z3core_a: amtrckr
{
	meta:
		family = "z3core"
	condition:
		androguard.url(/lexsmilefux\.link/)
}
rule thoughtcrime_b: amtrckr
{
	meta:
		family = "thoughtcrime"
	condition:
		androguard.url(/edda-mally\.at/) or 
		androguard.url(/www\.oguhtell\.ch/) or 
		androguard.url(/szaivert-numis\.at/) or 
		androguard.url(/clubk-ginza\.net/) or 
		androguard.url(/losbalonazos\.com/)
}
rule marcher_c: amtrckr
{
	meta:
		family = "marcher"
	condition:
		androguard.url(/104\.238\.176\.9/) or 
		androguard.url(/golioni\.tk/) or 
		androguard.url(/poloclubs\.tk/) or 
		androguard.url(/thejcb\.ru/) or 
		androguard.url(/shgt\.tk/) or 
		androguard.url(/pologt\.tk/) or 
		androguard.url(/108\.61\.211\.219/) or 
		androguard.url(/vipcoon\.com/) or 
		androguard.url(/firenzonne\.com/) or 
		androguard.url(/extgta\.tk/) or 
		androguard.url(/manaclubs\.tk/) or 
		androguard.url(/151\.248\.126\.183/) or 
		androguard.url(/188\.209\.49\.198/)
}
rule lenovo_reaper_a: amtrckr
{
	meta:
		family = "lenovo_reaper"
	condition:
		androguard.url(/uefsr\.lenovomm\.com/)
}
rule unknown_c: amtrckr
{
	meta:
		family = "unknown"
	condition:
		androguard.url(/222\.76\.213\.20/) or 
		androguard.url(/103\.38\.42\.236/) or 
		androguard.url(/103\.243\.181\.41/) or 
		androguard.url(/123\.1\.157\.4/)
}
rule jagonca_a: amtrckr
{
	meta:
		family = "jagonca"
	condition:
		androguard.url(/abra-k0dabra\.com/) or 
		androguard.url(/heibe-titten\.com/)
}
rule gtalocker_a: amtrckr
{
	meta:
		family = "gtalocker"
	condition:
		androguard.url(/niktoegoneyznaet0kol\.pw/)
}
rule slocker_a: amtrckr
{
	meta:
		family = "slocker"
	condition:
		androguard.url(/aerofigg\.org/)
}
rule infostealer_a: amtrckr
{
	meta:
		family = "infostealer"
	condition:
		androguard.url(/koko02\.ru/)
}
rule pornlocker_a: amtrckr
{
	meta:
		family = "pornlocker"
	condition:
		androguard.url(/playmarketcheck\.com/) or 
		androguard.url(/pornigy\.biz/)
}
rule droidian_a: amtrckr
{
	meta:
		family = "droidian"
	condition:
		androguard.url(/z0\.tkurd\.net/)
}
rule androrat_b: amtrckr
{
	meta:
		family = "androrat"
	condition:
		androguard.url(/haiderhacer12\.no-ip\.biz/) or 
		androguard.url(/toyman6699\.no-ip\.info/) or 
		androguard.url(/aerror\.no-ip\.biz/) or 
		androguard.url(/androrat\.servegame\.com/) or 
		androguard.url(/197\.35\.22\.37/) or 
		androguard.url(/androrat1\.no-ip\.biz/) or 
		androguard.url(/151\.72\.17\.61/) or 
		androguard.url(/recycled\.no-ip\.org/) or 
		androguard.url(/gert44\.duckdns\.org/) or 
		androguard.url(/78\.169\.63\.163/) or 
		androguard.url(/hash0r\.no-ip\.biz/) or 
		androguard.url(/alpheron\.duckdns\.org/) or 
		androguard.url(/cricbot\.no-ip\.info/) or 
		androguard.url(/hazhar77\.no-ip\.biz/) or 
		androguard.url(/aleem\.top7@gmail\.com/) or 
		androguard.url(/murryapplicazione\.no-ip\.org/) or 
		androguard.url(/helloandroid\.no-ip\.org/) or 
		androguard.url(/79\.170\.54\.154/) or 
		androguard.url(/xyz2145\.ddns\.net/) or 
		androguard.url(/mohammad2002\.no-ip\.biz/) or 
		androguard.url(/1756mostacc\.ddns\.net/) or 
		androguard.url(/shakaky\.ddns\.net/) or 
		androguard.url(/danialmostafaei\.no-ip\.biz/) or 
		androguard.url(/109\.95\.56\.22/) or 
		androguard.url(/dagohack\.no-ip\.me/) or 
		androguard.url(/pruebasernesto\.ddns\.net/) or 
		androguard.url(/androjan\.ddns\.net/) or 
		androguard.url(/132\.72\.81\.164/) or 
		androguard.url(/zongkahani\.no-ip\.biz/) or 
		androguard.url(/florian-pc\.ksueyuj0mtxpt6gn\.myfritz\.net/) or 
		androguard.url(/kontolanime\.no-ip\.biz/) or 
		androguard.url(/redcode\.ddns\.net/) or 
		androguard.url(/gentel901\.no-ip\.org/) or 
		androguard.url(/anonimousdre180\.ddns\.net/) or 
		androguard.url(/sajadianh\.ddns\.net/) or 
		androguard.url(/195\.2\.239\.147/) or 
		androguard.url(/vipmustafa\.no-ip\.info/) or 
		androguard.url(/martin123456\.no-ip\.org/) or 
		androguard.url(/alihoseini\.no-ip\.biz/) or 
		androguard.url(/aymen1852\.ddns\.net/) or 
		androguard.url(/zola123\.no-ip\.biz/) or 
		androguard.url(/androrat143\.no-ip\.biz/) or 
		androguard.url(/sabbah\.duckdns\.org/) or 
		androguard.url(/89\.95\.11\.159/) or 
		androguard.url(/telegram-tools\.no-ip\.biz/) or 
		androguard.url(/androrat1226\.ddns\.net/) or 
		androguard.url(/84\.241\.6\.106/) or 
		androguard.url(/linonymousami\.no-ip\.org/) or 
		androguard.url(/alldebrid\.duckdns\.org/) or 
		androguard.url(/187\.180\.186\.181/) or 
		androguard.url(/411022356/) or 
		androguard.url(/93\.82\.129\.5/) or 
		androguard.url(/mikestar\.no-ip\.biz/) or 
		androguard.url(/sherlockholmes\.duckdns\.org/) or 
		androguard.url(/adelxxbx\.no-ip\.biz/) or 
		androguard.url(/r3cxw\.ddns\.net/) or 
		androguard.url(/matgio\.duckdns\.org/) or 
		androguard.url(/glaive24\.no-ip\.biz/) or 
		androguard.url(/41\.143\.69\.230/) or 
		androguard.url(/151\.56\.227\.79/) or 
		androguard.url(/shahabhacker\.ddns\.net/) or 
		androguard.url(/186\.81\.50\.145/) or 
		androguard.url(/kasofe123123aa\.no-ip\.biz/) or 
		androguard.url(/tanha\.sit@gmail\.com/) or 
		androguard.url(/persir\.no-ip\.biz/) or 
		androguard.url(/androidupdate\.ddns\.net/) or 
		androguard.url(/charifo1310tok\.no-ip\.biz/) or 
		androguard.url(/securepurpose\.no-ip\.info/) or 
		androguard.url(/vpn0\.ddns\.net/) or 
		androguard.url(/usa20002015\.ddns\.net/) or 
		androguard.url(/duyguseliberkay\.no-ip\.biz/) or 
		androguard.url(/miltin2\.no-ip\.org/) or 
		androguard.url(/droidjack228\.ddns\.net/) or 
		androguard.url(/mjhooollltuuu\.no-ip\.biz/) or 
		androguard.url(/nexmopro830\.ddns\.net/) or 
		androguard.url(/rustyash\.no-ip\.biz/) or 
		androguard.url(/atsizinoglu\.duckdns\.org/) or 
		androguard.url(/goog2\.no-ip\.biz/) or 
		androguard.url(/testan\.ddns\.net/) or 
		androguard.url(/androrat\.zapto\.org/) or 
		androguard.url(/blackghostdc\.duckdns\.org/) or 
		androguard.url(/191\.239\.107\.56/) or 
		androguard.url(/kalinne\.ddns\.net/) or 
		androguard.url(/samy777\.no-ip\.biz/) or 
		androguard.url(/hackcam\.zapto\.org/) or 
		androguard.url(/kalizinho\.no-ip\.org/) or 
		androguard.url(/46\.223\.99\.222/) or 
		androguard.url(/karasqlee9\.no-ip\.org/) or 
		androguard.url(/andro0161\.no-ip\.info/) or 
		androguard.url(/84\.101\.0\.49/) or 
		androguard.url(/msupdate\.myvnc\.com/) or 
		androguard.url(/zal75zk\.ddns\.net/) or 
		androguard.url(/nassahsliman\.ddns\.net/) or 
		androguard.url(/mohsenfaz\.ddns\.net/) or 
		androguard.url(/moha55\.no-ip\.biz/) or 
		androguard.url(/106\.219\.57\.228/) or 
		androguard.url(/android\.no-ip\.org/) or 
		androguard.url(/161\.202\.108\.108/) or 
		androguard.url(/hamker\.ddns\.net/) or 
		androguard.url(/92\.243\.68\.167/) or 
		androguard.url(/vikas\.no-ip\.biz/) or 
		androguard.url(/68\.189\.1\.254/) or 
		androguard.url(/bmt96\.noip\.me/) or 
		androguard.url(/newxor2\.no-ip\.org/) or 
		androguard.url(/2\.190\.167\.83/) or 
		androguard.url(/hackme\.no-ip\.org/) or 
		androguard.url(/mohammedwasib\.ddns\.net/) or 
		androguard.url(/24\.172\.28\.155/) or 
		androguard.url(/120\.0\.0\.1/) or 
		androguard.url(/simbabweratte\.hopto\.org/) or 
		androguard.url(/100\.1\.254\.38/) or 
		androguard.url(/222\.168\.1\.2/) or 
		androguard.url(/189\.174\.125\.60/) or 
		androguard.url(/61\.131\.121\.195/) or 
		androguard.url(/suckmordecock\.duckdns\.org/) or 
		androguard.url(/201\.124\.95\.7/) or 
		androguard.url(/svn-01\.ddns\.net/) or 
		androguard.url(/jNkey\.ddns\.net/) or 
		androguard.url(/131\.117\.235\.35/) or 
		androguard.url(/justarat\.noip\.me/) or 
		androguard.url(/dangerlove\.no-ip\.biz/) or 
		androguard.url(/bahoom\.no-ip\.biz/) or 
		androguard.url(/183\.82\.99\.133/) or 
		androguard.url(/hatam\.no-ip\.org/) or 
		androguard.url(/37\.239\.8\.89/) or 
		androguard.url(/c1\.no-ip\.biz/) or 
		androguard.url(/141\.255\.144\.72/) or 
		androguard.url(/juanblackhak\.ddns\.net/) or 
		androguard.url(/saiber-far68\.ddns\.net/) or 
		androguard.url(/qwerty1212\.ddns\.net/) or 
		androguard.url(/androratbtas\.no-ip\.info/) or 
		androguard.url(/servidor23\.ddns\.net/) or 
		androguard.url(/replace\.duckdns\.org/) or 
		androguard.url(/war10ck\.serveftp\.com/) or 
		androguard.url(/myonline\.no-ip\.biz/) or 
		androguard.url(/anonsa\.ddns\.net/) or 
		androguard.url(/dogecoinspeed\.zapto\.org/) or 
		androguard.url(/174\.127\.99\.232/) or 
		androguard.url(/invisibleghost\.no-ip\.biz/) or 
		androguard.url(/elgen1\.no-ip\.biz/) or 
		androguard.url(/habbo\.no-ip\.org/) or 
		androguard.url(/makarand\.no-ip\.org/) or 
		androguard.url(/94\.212\.118\.115/) or 
		androguard.url(/41\.38\.56\.81/) or 
		androguard.url(/misty255\.no-ip\.org/) or 
		androguard.url(/volnado\.sytes\.net/) or 
		androguard.url(/asadhashmi\.ddns\.net/) or 
		androguard.url(/asosha4ed\.no-ip\.biz/) or 
		androguard.url(/losever2\.no-ip\.biz/) or 
		androguard.url(/80\.136\.103\.51/) or 
		androguard.url(/drrazikhan\.no-ip\.info/) or 
		androguard.url(/thekillers\.ddns\.net/) or 
		androguard.url(/isamdonita\.no-ip\.org/) or 
		androguard.url(/anagliz\.ddns\.net/)
}
rule sandrorat_c: amtrckr
{
	meta:
		family = "sandrorat"
	condition:
		androguard.url(/tak\.no-ip\.info/) or 
		androguard.url(/jomo\.zapto\.org/) or 
		androguard.url(/sondres1\.ddns\.net/) or 
		androguard.url(/mehost\.ddns\.net/) or 
		androguard.url(/toyman6699\.no-ip\.info/) or 
		androguard.url(/hax\.no-ip\.info/) or 
		androguard.url(/31\.210\.117\.132/) or 
		androguard.url(/fairylow\.no-ip\.biz/) or 
		androguard.url(/changyu231\.ddns\.net/) or 
		androguard.url(/cjbks0u0\.no-ip\.org/) or 
		androguard.url(/mohammed22468\.no-ip\.biz/) or 
		androguard.url(/46\.186\.155\.219/) or 
		androguard.url(/jockerhackerxnxx\.ddns\.net/) or 
		androguard.url(/41\.251\.251\.7/) or 
		androguard.url(/engrid\.no-ip\.biz/) or 
		androguard.url(/megalol\.chickenkiller\.com/) or 
		androguard.url(/188\.166\.76\.144/) or 
		androguard.url(/sarahwygan\.no-ip\.biz/) or 
		androguard.url(/injectman\.no-ip\.info/) or 
		androguard.url(/aasxzxdsc12324\.no-ip\.biz/) or 
		androguard.url(/khantac\.ddns\.net/) or 
		androguard.url(/alfazaai99\.ddns\.net/) or 
		androguard.url(/dantehack\.zapto\.org/) or 
		androguard.url(/droidjack1\.sytes\.net/) or 
		androguard.url(/th3expert\.3utilities\.com/) or 
		androguard.url(/mohamed46565656\.no-ip\.biz/) or 
		androguard.url(/chrisfo\.no-ip\.org/) or 
		androguard.url(/jkgytgasjg12\.serveftp\.com/) or 
		androguard.url(/hazhar77\.no-ip\.biz/) or 
		androguard.url(/31\.146\.202\.169/) or 
		androguard.url(/njesra\.ddns\.net/) or 
		androguard.url(/hamidoranis\.no-ip\.biz/) or 
		androguard.url(/yorkiepet\.ddns\.net/) or 
		androguard.url(/mrgnet\.ddns\.net/) or 
		androguard.url(/droy\.zapto\.org/) or 
		androguard.url(/93\.104\.213\.217/) or 
		androguard.url(/amarok58\.no-ip\.biz/) or 
		androguard.url(/server4update\.serveftp\.com/) or 
		androguard.url(/zaliminxx\.duckdns\.org/) or 
		androguard.url(/anonymo9s\.ddns\.net/) or 
		androguard.url(/htmp\.sytes\.net/) or 
		androguard.url(/khalid-2016\.noip\.me/) or 
		androguard.url(/mahasiswa\.no-ip\.biz/) or 
		androguard.url(/kaddress\.ddns\.net/) or 
		androguard.url(/sharmayash\.no-ip\.biz/) or 
		androguard.url(/shabbushah\.duckdns\.org/) or 
		androguard.url(/osammer0asmam3a\.ddns\.net/) or 
		androguard.url(/themayhen23\.no-ip\.org/) or 
		androguard.url(/wxf2009817\.f3322\.net/) or 
		androguard.url(/miioolinase\.ddns\.net/) or 
		androguard.url(/motoshi\.zapto\.org/) or 
		androguard.url(/88\.150\.149\.91/) or 
		androguard.url(/info\.bounceme\.net/) or 
		androguard.url(/samira\.no-ip\.biz/) or 
		androguard.url(/mohamednjrat111\.no-ip\.biz/) or 
		androguard.url(/31\.210\.69\.156/) or 
		androguard.url(/futurasky\.no-ip\.biz/) or 
		androguard.url(/rat\.capsulelab\.us/) or 
		androguard.url(/fruby\.zapto\.org/) or 
		androguard.url(/samsung\.apps\.linkpc\.net/) or 
		androguard.url(/eldiablo\.no-ip\.biz/) or 
		androguard.url(/system32\.com/) or 
		androguard.url(/alkingahmed555\.ddns\.net/) or 
		androguard.url(/haker33sadekgafer\.no-ip\.biz/) or 
		androguard.url(/droidjack258\.bounceme\.net/) or 
		androguard.url(/fazoro66\.ddns\.net/) or 
		androguard.url(/androidalbums\.ddns\.net/) or 
		androguard.url(/tedy1993\.ddns\.net/) or 
		androguard.url(/alaa-1982\.no-ip\.biz/) or 
		androguard.url(/facrbook\.redirectme\.net/) or 
		androguard.url(/androidan\.ddns\.net/) or 
		androguard.url(/learnxea\.duckdns\.org/) or 
		androguard.url(/audreysaradin\.no-ip\.org/) or 
		androguard.url(/microsoft-office\.ddns\.net/) or 
		androguard.url(/178\.124\.182\.38/) or 
		androguard.url(/mobiles0ft\.no-ip\.org/) or 
		androguard.url(/cybercrysis\.ddns\.net/) or 
		androguard.url(/playstore\.ddns\.net/) or 
		androguard.url(/amran-pc\.no-ip\.biz/) or 
		androguard.url(/chanks\.no-ip\.biz/) or 
		androguard.url(/lomo\.com/) or 
		androguard.url(/ayadd19\.no-ip\.org/) or 
		androguard.url(/bitoandroid\.no-ip\.info/) or 
		androguard.url(/androidtool\.ddns\.net/) or 
		androguard.url(/authd\.ddns\.net/) or 
		androguard.url(/carapuce-2015\.no-ip\.biz/) or 
		androguard.url(/aliyusef6\.no-ip\.biz/) or 
		androguard.url(/bannding\.ddns\.net/) or 
		androguard.url(/wogusnb\.no-ip\.info/) or 
		androguard.url(/noussa\.no-ip\.biz/) or 
		androguard.url(/droidjackv5\.ddns\.net/) or 
		androguard.url(/mzgerges\.no-ip\.biz/) or 
		androguard.url(/androidrat21\.ddns\.net/) or 
		androguard.url(/RATForAndroid\.ddns\.net/) or 
		androguard.url(/178\.20\.230\.44/) or 
		androguard.url(/strateg\.ddns\.net/) or 
		androguard.url(/hasn9999\.ddns\.net/) or 
		androguard.url(/mahdi3141\.ddns\.net/) or 
		androguard.url(/fucks\.ddns\.net/) or 
		androguard.url(/shahidsajan\.no-ip\.biz/) or 
		androguard.url(/spicymemes\.duckdns\.org/) or 
		androguard.url(/hackermoqtada\.no-ip\.biz/) or 
		androguard.url(/andro\.no-ip\.biz/) or 
		androguard.url(/goggle\.sytes\.net/) or 
		androguard.url(/anonymous666\.zapto\.org/) or 
		androguard.url(/dnsdynamic\.org/) or 
		androguard.url(/maskaralama\.ddns\.net/) or 
		androguard.url(/adobflash\.hopto\.org/) or 
		androguard.url(/iqram85spy\.ddns\.net/) or 
		androguard.url(/moussa-hak\.no-ip\.biz/) or 
		androguard.url(/shoo2018\.no-ip\.org/) or 
		androguard.url(/22134520\.ddns\.net/) or 
		androguard.url(/109\.122\.41\.237/) or 
		androguard.url(/137\.0\.0\.1/) or 
		androguard.url(/droidjack\.hopto\.org/) or 
		androguard.url(/brave-hacker\.no-ip\.org/) or 
		androguard.url(/huntergold\.no-ip\.biz/) or 
		androguard.url(/hakeerali2\.ddns\.net/) or 
		androguard.url(/seven1\.ddns\.net/) or 
		androguard.url(/younix\.ddns\.net/) or 
		androguard.url(/dkms\.ddns\.net/) or 
		androguard.url(/abdouoahmed\.ddns\.net/) or 
		androguard.url(/hehe\.duckdns\.org/) or 
		androguard.url(/hardstyleraver\.no-ip\.org/) or 
		androguard.url(/85\.136\.243\.80/) or 
		androguard.url(/sarasisi\.no-ip\.org/) or 
		androguard.url(/yelp01\.f3322\.org/) or 
		androguard.url(/teolandia\.no-ip\.biz/) or 
		androguard.url(/jokerbabel\.no-ip\.biz/) or 
		androguard.url(/cccamd\.myftp\.biz/) or 
		androguard.url(/109\.165\.69\.25/) or 
		androguard.url(/vb\.blogsyte\.com/) or 
		androguard.url(/karrarhuseein82\.ddns\.net/) or 
		androguard.url(/applecenikosmos\.hldns\.ru/) or 
		androguard.url(/madov-matrix25\.no-ip\.org/) or 
		androguard.url(/1349874791\.gnway\.cc/) or 
		androguard.url(/bapforall\.ddns\.net/) or 
		androguard.url(/mahamadmahmod\.ddns\.net/) or 
		androguard.url(/42\.236\.159\.93/) or 
		androguard.url(/msn-web\.ddnsking\.com/) or 
		androguard.url(/draagon\.ddns\.net/) or 
		androguard.url(/winlogen\.duckdns\.org/) or 
		androguard.url(/albash2222\.ddns\.net/) or 
		androguard.url(/ahmed2012\.dynu\.com/) or 
		androguard.url(/188\.3\.13\.98/) or 
		androguard.url(/clashdroid\.no-ip\.biz/) or 
		androguard.url(/hardik\.no-ip\.info/) or 
		androguard.url(/asdqqq\.bounceme\.net/) or 
		androguard.url(/housam\.linkpc\.net/) or 
		androguard.url(/hackhack2016\.no-ip\.info/) or 
		androguard.url(/pars\.ddns\.net/) or 
		androguard.url(/noiphackk\.ddns\.net/) or 
		androguard.url(/islam2020libya\.no-ip\.biz/) or 
		androguard.url(/dodee97dodee\.ddns\.net/) or 
		androguard.url(/anonymousip\.no-ip\.org/) or 
		androguard.url(/haxor\.hopto\.org/) or 
		androguard.url(/zokor-zokor\.ddns\.net/) or 
		androguard.url(/xzoro2016\.no-ip\.info/) or 
		androguard.url(/81\.177\.33\.218/) or 
		androguard.url(/107\.151\.193\.126/) or 
		androguard.url(/bassamzeyad\.ddns\.net/) or 
		androguard.url(/momo2015\.duckdns\.org/) or 
		androguard.url(/scropion20078\.no-ip\.biz/) or 
		androguard.url(/106\.51\.163\.232/) or 
		androguard.url(/fuckyou\.duckdns\.org/) or 
		androguard.url(/zakifr\.no-ip\.biz/) or 
		androguard.url(/82\.223\.31\.121/) or 
		androguard.url(/2\.25\.171\.244/) or 
		androguard.url(/85\.202\.29\.79/) or 
		androguard.url(/mariorossi2013\.homepc\.it/) or 
		androguard.url(/hackcam\.zapto\.org/) or 
		androguard.url(/dexonic\.duckdns\.org/) or 
		androguard.url(/mokhter222029\.ddns\.net/) or 
		androguard.url(/win32\.ddns\.net/) or 
		androguard.url(/ggwasgeht\.ddns\.net/) or 
		androguard.url(/randsnaira\.dnsdynamic\.com/) or 
		androguard.url(/coxiamigo\.myq-see\.com/) or 
		androguard.url(/googles\.servemp3\.com/) or 
		androguard.url(/ospr\.publicvm\.com/) or 
		androguard.url(/karasqlee9\.no-ip\.org/) or 
		androguard.url(/haa7aah\.no-ip\.biz/) or 
		androguard.url(/omar\.no-ip\.biz/) or 
		androguard.url(/goldeneagle1112\.ddns\.net/) or 
		androguard.url(/yuosaf1993\.ddns\.net/) or 
		androguard.url(/88\.164\.37\.97/) or 
		androguard.url(/indusv00\.duckdns\.org/) or 
		androguard.url(/droid\.deutsche-db-bank\.ru/) or 
		androguard.url(/unknownuser\.no-ip\.biz/) or 
		androguard.url(/oneriakosa\.ddns\.net/) or 
		androguard.url(/gcafegood\.noip\.me/) or 
		androguard.url(/rockrock\.ddns\.net/) or 
		androguard.url(/188\.24\.119\.27/) or 
		androguard.url(/93\.157\.235\.248/) or 
		androguard.url(/komplevit-rat\.ddns\.net/) or 
		androguard.url(/pianotiles2\.ddns\.net/) or 
		androguard.url(/tobytori18\.myftp\.org/) or 
		androguard.url(/105\.106\.49\.154/) or 
		androguard.url(/moonmar10\.no-ip\.biz/) or 
		androguard.url(/100009755836320\.no-ip\.biz/) or 
		androguard.url(/kararkarar0780\.ddns\.net/) or 
		androguard.url(/foxfeline\.no-ip\.org/) or 
		androguard.url(/kskdt\.ddns\.net/) or 
		androguard.url(/fati43030\.no-ip\.biz/) or 
		androguard.url(/freeann\.sytes\.net/) or 
		androguard.url(/a\.tomx\.xyz/) or 
		androguard.url(/r90\.no-ip\.biz/) or 
		androguard.url(/41\.38\.56\.81/) or 
		androguard.url(/46\.45\.207\.81/) or 
		androguard.url(/warrirrs\.no-ip\.org/) or 
		androguard.url(/azert123\.ddns\.net/) or 
		androguard.url(/soso\.noip\.us/) or 
		androguard.url(/hassanabd1233\.ddns\.net/) or 
		androguard.url(/thaer\.no-ip\.biz/) or 
		androguard.url(/baby\.webhop\.me/) or 
		androguard.url(/zero228\.ddns\.net/) or 
		androguard.url(/reddemon\.ddns\.net/) or 
		androguard.url(/viagra\.jumpingcrab\.com/) or 
		androguard.url(/domira\.ddns\.net/) or 
		androguard.url(/nassahsliman\.ddns\.net/) or 
		androguard.url(/magemankoktelam\.ddns\.net/) or 
		androguard.url(/somenormalguy\.duckdns\.org/) or 
		androguard.url(/usa2222\.ddns\.net/) or 
		androguard.url(/aaaaaaaaaabbbbb\.hopto\.org/) or 
		androguard.url(/cardangi\.no-ip\.org/) or 
		androguard.url(/151\.246\.230\.21/) or 
		androguard.url(/79\.141\.163\.20/) or 
		androguard.url(/mezoo32\.no-ip\.biz/) or 
		androguard.url(/hack1111\.noip\.me/) or 
		androguard.url(/kingdom\.no-ip\.biz/) or 
		androguard.url(/x300x300xx\.no-ip\.org/) or 
		androguard.url(/puplicdsl\.ddns\.net/) or 
		androguard.url(/shanks\.no-ip\.biz/) or 
		androguard.url(/teda11\.zapto\.org/) or 
		androguard.url(/testsss\.ddns\.net/) or 
		androguard.url(/185\.32\.221\.23/) or 
		androguard.url(/topmax\.myq-see\.com/) or 
		androguard.url(/iraqn6777\.ddns\.net/) or 
		androguard.url(/pimpdaddy\.myq-see\.com/) or 
		androguard.url(/villevalo\.chickenkiller\.com/) or 
		androguard.url(/hhamokcha\.ddns\.net/) or 
		androguard.url(/jastn\.ddns\.net/) or 
		androguard.url(/flashplayerxx\.no-ip\.org/) or 
		androguard.url(/sniperyakub\.ddns\.net/) or 
		androguard.url(/elisou19\.ddns\.net/) or 
		androguard.url(/88\.247\.226\.120/) or 
		androguard.url(/aaaa\.com/) or 
		androguard.url(/moep004\.no-ip\.org/) or 
		androguard.url(/liquidixen\.ddns\.net/) or 
		androguard.url(/rok13198666\.no-ip\.biz/) or 
		androguard.url(/mamal9921\.ddns\.net/) or 
		androguard.url(/droidjack33\.no-ip\.biz/) or 
		androguard.url(/diceedicee\.ddns\.net/) or 
		androguard.url(/e777kx47\.ddns\.net/) or 
		androguard.url(/evilcasper\.ddns\.net/) or 
		androguard.url(/black1990\.ddns\.net/) or 
		androguard.url(/appmarket\.servehttp\.com/) or 
		androguard.url(/thegangsterrap\.noip\.me/) or 
		androguard.url(/ala6a\.no-ip\.biz/) or 
		androguard.url(/myaw\.no-ip\.biz/) or 
		androguard.url(/nademhack\.no-ip\.org/) or 
		androguard.url(/shop10\.ddns\.net/) or 
		androguard.url(/xos1982\.ddns\.net/) or 
		androguard.url(/93\.185\.151\.217/) or 
		androguard.url(/203\.189\.232\.237/) or 
		androguard.url(/zxczxczxc\.ddns\.net/) or 
		androguard.url(/07726657423zaion\.no-ip\.biz/) or 
		androguard.url(/blind1234\.ddns\.net/) or 
		androguard.url(/myfrenid2x\.zapto\.org/) or 
		androguard.url(/winserver\.dlinkddns\.com/) or 
		androguard.url(/alanbkey\.no-ip\.org/) or 
		androguard.url(/williettinger\.cc/) or 
		androguard.url(/silenthunter3021\.no-ip\.org/) or 
		androguard.url(/1337ace\.ddns\.net/) or 
		androguard.url(/test\.no-ip\.org/) or 
		androguard.url(/snopi\.no-ip\.biz/) or 
		androguard.url(/andver18\.no-ip\.biz/) or 
		androguard.url(/kilasx\.ddns\.net/) or 
		androguard.url(/109\.73\.68\.114/) or 
		androguard.url(/owsen\.ddns\.net/) or 
		androguard.url(/android1\.ddns\.net/) or 
		androguard.url(/81\.4\.104\.129/) or 
		androguard.url(/bambi\.no-ip\.biz/) or 
		androguard.url(/egytiger\.myftp\.org/) or 
		androguard.url(/gold5000\.ddns\.net/) or 
		androguard.url(/makarand\.no-ip\.org/) or 
		androguard.url(/93\.79\.212\.194/) or 
		androguard.url(/denishul\.hldns\.ru/) or 
		androguard.url(/hacker-81\.no-ip\.biz/) or 
		androguard.url(/noipjajaja\.ddns\.net/) or 
		androguard.url(/samoomalik\.no-ip\.biz/) or 
		androguard.url(/tataline\.hopto\.org/) or 
		androguard.url(/abedjaradat1177\.no-ip\.org/) or 
		androguard.url(/voda\.no-ip\.org/) or 
		androguard.url(/dadadadadaprivet\.ddns\.net/) or 
		androguard.url(/darweshfis\.no-ip\.org/) or 
		androguard.url(/5\.189\.137\.186/) or 
		androguard.url(/79\.137\.223\.139/) or 
		androguard.url(/love2014\.ddns\.net/) or 
		androguard.url(/momen-swesi\.no-ip\.biz/) or 
		androguard.url(/xmohcine\.ddns\.net/) or 
		androguard.url(/alabama192837\.no-ip\.org/)
}
rule ibanking_a: amtrckr
{
	meta:
		family = "ibanking"
	condition:
		androguard.url(/www\.irmihan\.ir/) or 
		androguard.url(/emberaer\.com/)
}
rule hacking_team_b: stcert
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
rule Banker_h:Gugi
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
rule ransomware_i
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
rule wormHole_b
{
	meta:
		description = "Wormhome vulnerability found in com.qihoo.secstore con GPlay. After app launch, a SimpleWebServer service is called listening to 0.0.0.0:38517. It uses yunpan to upload files and get a 360 domain. App protected by proguard."
	strings:
		$a = "/getModel0" 
		$b = "/in" // download and install apk
		$c = "/openPage" // Open URL
		$d = "/openActivity" // Launch activity
		$e = "/isAppInstalled" // Check app existance
		$f = ".360.cn" 
		$g = ".so.com" 
		$h = ".qihoo.net"
		$i = ".gamer.cn"
	condition:
		($a or $b or $c or $d or $e) and ($f or $g or $h  or $i)
}
rule Kemoge_b: official
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
rule whatsapp_b:fake
{
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}
rule king_games_b:fake
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
		and not androguard.certificate.sha1("F22BD3F8C24AB1451ABFD675788B953C325AB550")
}

rule instagram_b:fake
{
	condition:
		androguard.app_name("Instagram")
		and not androguard.certificate.sha1("C56FB7D591BA6704DF047FD98F535372FEA00211")
}
rule BankBot_d
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
rule BankBot2_b
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
rule andr_tordow_a
{
	meta:
		description = "Yara for variants of Trojan-Banker.AndroidOS.Tordow. Test rule"
		source = "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/"
		author = "https://twitter.com/5h1vang"
	condition:
		androguard.package_name("com.di2.two") or		
		(androguard.activity(/API2Service/i) and
		androguard.activity(/CryptoUtil/i) and
		androguard.activity(/Loader/i) and
		androguard.activity(/Logger/i) and 
		androguard.permission(/android.permission.INTERNET/)) or
		androguard.certificate.sha1("78F162D2CC7366754649A806CF17080682FE538C") or
		androguard.certificate.sha1("BBA26351CE41ACBE5FA84C9CF331D768CEDD768F") or
		androguard.certificate.sha1("0B7C3BC97B6D7C228F456304F5E1B75797B7265E")
}
rule dresscode_a: trojan
{
    meta:
        description = "DressCode proxy bot: http://blog.checkpoint.com/2016/08/31/dresscode-android-malware-discovered-on-google-play/"
    strings:
	  $a = "REQUEST_CREATE"
	  $b = "REQUEST_HELLO"
	  $c = "REQUEST_PING"
	  $d = "REQUEST_SLEEP"
	  $e = "REQUEST_WAIT"
	  $f = "RESPONSE_HELLO"
	  $g = "RESPONSE_PONG"
    condition:
        ($a and $b and $c and $d and $e and $f and $g) or 
        (androguard.service(/com\.a\.c\.Service/) and androguard.receiver(/com\.a\.c\.Receiver/))
}
rule VikingBotnet_a
{
	meta:
		description = "Rule to detect Viking Order Botnet."
		sample = "85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c"
	strings:
		$a = "cv7obBkPVC2pvJmWSfHzXh"
		$b = "http://joyappstech.biz:11111/knock/"
		$c = "I HATE TESTERS onGlobalLayout"
		$d = "http://144.76.70.213:7777/ecspectapatronum/"
		$e = "http://176.9.138.114:7777/ecspectapatronum/"
		$f = "http://telbux.pw:11111/knock/"
	condition:
		($a and $c) or ($b or $d or $e or $f) 
}
rule trojanSMS_c
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
rule Android_Anubis_v3_b
{
	meta:
		author = "Jacob Soo Lead Re"
		description = "Anubis newer version."
	condition:
		(androguard.filter(/android.intent.action.DREAMING_STOPPED/i) 
		and androguard.filter(/android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE/i) 
		and androguard.filter(/android.intent.action.USER_PRESENT/i))
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
rule Pegasus_a: official
{
	meta:
		description = "This rule detects Pegasus variants"
		sample = "ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5"
		link_one = "https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-android-technical-analysis.pdf"
		link_two = "https://android-developers.googleblog.com/2017/04/an-investigation-of-chrysaor-malware-on.html"
	strings:
		$string_varone_1 = "/system/csk"
		$string_varone_2 = "SystemJumper"
		$string_varone_3 = "TO_REMOVE:)"
		$string_varone_4 = "copyMySuFileToSystem"
		$string_varone_5 = "shouldSuicide"
		$string_vartwo_1 = "NetworkMain"
		$string_vartwo_2 = "network.android/libsgn.so"
		$string_varthree_1 = "chmod isSu :"
		$string_varthree_2 = "getApkInfos"
		$string_varthree_3 = "has_phone_number"
		$string_varthree_4 = "pegasus"
		$string_varthree_5 = "systemCall end:"
	condition:
	(all of ($string_varone_*) ) or
	(all of ($string_vartwo_*) ) or
	(all of ($string_varthree_*) and $string_varone_1 ) or
	androguard.certificate.sha1("516f8f516cc0fd8db53785a48c0a86554f75c3ba") or 
	androguard.certificate.sha1("44f6d1caa257799e57f0ecaf4e2e216178f4cb3d") or 
	androguard.certificate.sha1("7771af1ad3a3d9c0b4d9b55260bb47c2692722cf") or
	androguard.certificate.sha1("31a8633c2cd67ae965524d0b2192e9f14d04d016")
}
rule Mazain_c: Banker
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
rule porn_a: chinese
{
	condition:
		androguard.url(/www\.4006000790\.com/) or
		androguard.url(/wap\.xykernel\.cn/) or
		androguard.url(/aaxzz\.b0\.upaiyun\.com/) or
		cuckoo.network.dns_lookup(/wap\.xykernel\.cn/) or
		cuckoo.network.dns_lookup(/androd2\.video\.daixie800\.com/) or
		cuckoo.network.dns_lookup(/www\.4006000790\.com/)
}
rule towelhacking_behaviour_a
{
	meta:
		description = "Search probably apks relationships"
		sample = ""
	condition:
		androguard.certificate.sha1("180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E") or 
		( androguard.activity(/net.prospectus.*/i) and androguard.permission(/android.permission.WRITE_CONTACT/) and
		androguard.permission(/android.permission.ACCESS_COARSE_UPDATES/))
}
rule towelhacking_analysis_a
{
	meta:
		description = "From static analysis"
		sample = "258c34428e214d2a49d3de776db98d26e0bd0abc452249c8be8cdbcb10218e8c"
	strings:
		$analysis_a = "LoganberryApplication"
		$analysis_b = "attachBaseContext"
		$analysis_c = "Obstetric"
	condition:
		all of them
}
rule towelhacking_cromosome_a
{
	meta:
		description = "From cromosome.py"
		sample = ""
	strings:
		$cromosome_a = "res/xml/device_admin_data.xml]"
	  	$cromosome_b = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACABAMAAAAxEHz4AAAAGFBMVEVMaXGUwUWTwEaTwEaTwEaTwEaVwUWTwEalNfqIAAAAB3RSTlMALozOuetYmPN8xgAAAbFJREFUeF7t2E9L+zAcx/FP1i3n7PfHXauivW7K3HWAY1dFoNci2l61Lvs8fUOxZYW22RdBBub1AN4kX7KQDqcvCILgDC0aUlcGhzaQ+j/HAb2HlC5buTXEEoMGlgZikzkAledTAKM95HSJPxs6T9eYrSGHZMMvuyXkoLZs2AxyCQ98GEi9sqWEkGYb1/INMGUtFW9iRDLWdWGhtuQCEgW5a+ZIgwn5AQFVjQ0zViwQkYwFgYjVCorDFfBdtgMyU80MkFC2h5SOXfGLXbIqyg9B2xzHGrODZAgzdioFM+y0E5zjThbHurzthl9Bb24M8HLfzQCXT+cYsiX3QMJuBn9Jazz3CLOBwIrko+8IzvsDmk7pO4Lv/YExPT/rxBOI6NjTCIRACIRACITA2BeY0XnoD4x8D5WITtwfUKnnraVScof+AArfk/cfbTwU0CveYdDUYCgANYXPYKBx+oEQKL772I7YaS/+cG+zMY6m8vyFDnOnqpV5nkFkVI+tvmWAXxkIgRDQdGxzO7xBSqX1B9qEzhpiBcmHei3WQEyn9d9fr+QCcji7yFDB8zV+QhAEQfAJcs5K2TAQqxAAAAAASUVORK5CYII="
		$cromosome_c = "device_admin_desc"
		$cromosome_d = "PillagedActivity"
		$cromosome_e = "EpigraphyService"
	condition:
		($cromosome_a and $cromosome_b) or ($cromosome_c and $cromosome_d and $cromosome_e)
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
rule kemoge_b
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
rule FamilyDroidKungFu_a
{
	meta:
		description = "Prevents FamilyDroidKungFu from activating"  
	strings:
		$a = "/system/app/com.google.ssearch.apk"
		$b = "/data/app/com.allen.mp-1.apk"
	condition:
		($a or $b)
}
rule koodous_vaa: official
{
	meta:
		description = "Rule to detect Cajino"
		sample = "Cajino_B3814CA9E42681B32DAFE4A52E5BDA7A"
	strings:
		$a = "/update/update.apk"
		$b = "application/vnd.android.package-archive"
	condition:
		androguard.package_name("com.koodous.android") and
		androguard.app_name("Koodous") and
		androguard.activity(/Details_Activity/i) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.ACCESS_FINE_LOCATION/) and
		androguard.permission(/android.permission.READ_CALL_LOG/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.READ_PHONE_NUMBERS/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.url("http://kharon.gforge.inria.fr\\dataset\\malware_Cajino.html") and 
		$a and 
		$b and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
}
rule test1_a: test
{
	meta:
		description = "This is a test"
	condition:
		true
}
rule koodous_waa: official
{
	meta:
		description = "SaveMe"
		sample = "saveme_78835947CCA21BA42110A4F206A7A486"
		reference = "http://kharon.gforge.inria.fr/dataset/malware_SaveMe.html"
	strings:
		$a = "content://call_log/calls"
		$b = "http://topemarketing.com/app.html"
		$c = "android.intent.action.CALL"
		$d = "content://icc/adn"
	condition:
		all of them
}
rule Cajino_g
{
	meta:
		name = "Olav Witvliet, Long Long Chen"
		Studentnumber = "s2642964, s2403846"
		Description = "Rule to detect Cajino (remote controlled spyware)"
		Reference = "http://kharon.gforge.inria.fr/dataset/malware_Cajino.html"
	strings:
		$a = "com.baidu.android.pushservice.action.MESSAGE"
		$b = "com.baidu.android.pushservice.action.RECEIVE"
		$c = "com.baidu.android.pushservice.action.notification.CLICK"
	condition:
		all of them
}
rule qq_a: malicious apk
{
	meta:
		description = "This rule detects the apk qq[NOT DETECTED] and similar apks"
		sample = "b09efef6d7ebd0f793fc7584cfa73181b54c3861fa7c00e7e172b889cd50102d"
	strings:
        $interesting_string = "xmlpull.org/v1/doc/features.html#indent-output" nocase
		$http_request = "data.flurry.com/aap.do"
		$calls_highlighted_1 = "android.location.LocationManager.getLastKnownLocation" nocase
		$calls_highlighted_2 = "android.telephony.TelephonyManager.getNetworkOperator" nocase
		$calls_highlighted_3 = "android.telephony.TelephonyManager.getNetworkOperatorName" nocase
		$calls_highlighted_4 = "android.util.Base64.decode" nocase
		$calls_highlighted_5 = "android.util.Base64.encode" nocase
		$calls_highlighted_6 = "javax.crypto.Cipher.doFinal" nocase
		$cryptographical_algorithms_observed = "AES" nocase
		$cryptographical_keys_observed = "UYGy723!Po-efjve"
		$encoding_algorithms_observed = "base64" nocase
		$decoded_text = "com.tencent.igx" nocase
		$highlighted_text_1 = "Enter password" nocase
		$highlighted_text_2 = "password-input" nocase
		$highlighted_text_3 = "Cancel" nocase
		$highlighted_text_4 = "OK" nocase
	condition:
		androguard.package_name("com.hughu") or
		androguard.app_name("qq[NOT DETECTED]") or
		androguard.certificate.sha1("967fad7b875343b14a84d3c240210941074e6cb7") or 
		(
			androguard.activity("com.applisto.appremium.classes.PasswordActivity") and
			androguard.activity("com.koushikdutta.superuser.RequestActivity") and
			androguard.permission(/android.permission.INTERNET/) and
			androguard.permission(/android.permission.ACCESS_NETWORK_STATE/) and
			(
				$interesting_string or
				$http_request or
				any of ($calls_highlighted_*) or
				$cryptographical_algorithms_observed or
				$cryptographical_keys_observed or
				$encoding_algorithms_observed or
				$decoded_text or
				all of ($highlighted_text_*)
			)
		)			
}
rule SimpLocker_c: official
{
	meta:
		description = "This rule detects the SimpLocker application, and applications like it"
		sample = "fd694cf5ca1dd4967ad6e8c67241114c"
	condition:
		androguard.app_name("SimpLocker") and
		androguard.activity(/android.intent.action.BOOT_COMPLETED/) and
		androguard.permission(/android.permission.INTERNET/)
}
rule Media_Player_a: official
{
	meta:
		description = "This rule detects the Media Player application, hoping to stop other malware like it"
		sample = "026ebdbc5cb2f6bd33705b9342231961"
	condition:
		androguard.package_name("com.BestGame.StickmanOnlineWarriors3") and
		cuckoo.network.dns_lookup(/drius.aefrant.com/)
}
rule Trojan_m: SnacksRecipes
{
	meta:
		description = "Trojan targeting mobile devices through the use of an application"
		sample = "7bd03a855da59f3a3255cf5c7535bc29"
	condition:
		androguard.package_name("com.androidgenieapps.snacksrecipes") and
		androguard.app_name("SnacksRecipes") and
        androguard.activity(/com.chownow.lemoncuisineofindia.sdk.activity.StartActivity/i) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.GET_TASKS/)
}
rule SaveMe_c: remote controlled spyware
{
	meta:
		description = "This rule detects the apk 'SaveMe' and similar apks"
	strings:
		$send_SMS_1 = "Send_ESms" nocase
		$send_SMS_2 = "SmsManager" nocase
		$send_SMS_3 = "sendTextMessage" nocase
		$display_webView = "WindowManager" nocase
		$make_call_1 = "android.intent.action.CALL" nocase
		$make_call_2 = "tel:" nocase
		$make_call_3 = "EXT_CALL" nocase
		$delete_call_1 = "content://call_log/calls" nocase
		$delete_call_2 = "number=?" nocase
		$end_call_1 = "com.android.internal.telephony.ITelephony" nocase
		$end_call_2 = "android.os.ServiceManager" nocase
		$end_call_3 = "android.os.ServiceManagerNative" nocase
		$end_call_4 = "getService" nocase
		$end_call_5 = "asInterface" nocase
		$end_call_6 = "fake" nocase
		$end_call_7 = "phone" nocase
		$end_call_8 = "endCall" nocase
		$steal_contacts_1 = "content://icc/adn" nocase		
		$steal_contacts_2 = "getColumnIndex" nocase
		$steal_contacts_3 = "name" nocase
		$steal_contacts_4 = "number" nocase		
		$steal_contacts_5 = "PHONE APP" nocase
		$steal_contacts_6 = "DatabaseOperations" nocase		
		$steal_contacts_7 = "sendcontact" nocase
		$pickContact_sendSMS = "deleteUser" nocase
		$remove_icon_1 = "setComponentEnabledSetting" nocase
		$remove_icon_2 = "COMPONENT_ENABLED_STATE_DISABLED" nocase
		$remove_icon_3 = "DONT_KILL_APP" nocase
	condition:
		androguard.app_name("SaveMe") or
        (
			any of ($send_SMS_*) and
			$display_webView and
			any of ($make_call_*) and
			any of ($delete_call_*) and
			any of ($end_call_*) and
			any of ($steal_contacts_*) and
			$pickContact_sendSMS and
			any of ($remove_icon_*)
		)
}
rule koodous_xaa: official
{
	meta:
		name = "Olav Witvliet, Long Long Chen"
		Studentnumber = "s2642964, s2403846"
		description = "This rule detects the malicious apk called Media Player by searching for suspicious strings and conditions"
		sample = "d79e71c4801b90d68cfcc7c913148151b31b3f79612b748ccfd5ed51257e9834"
	strings:
		$a = "http://drius.aefrant.com/"
	condition:
		androguard.package_name("air.com.KalromSystems.VoiceDrawFree") and
		androguard.app_name("Media Player") and
		androguard.permission(/android.permission.ACCESS_COARSE_LOCATION/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		$a
}
rule koodous_yaa: official
{
	meta:
		description = "This rule detects the AntiVirus app by Bechtelar Russel and Reinger"
		sample = "ea4cb7e998f6ec91156c81334cc862a8647642a43ca2dc918b7ef08dd0b54eae"
	strings:
		$a = "http://checkip.amazonaws.com/."
		$b = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"
	condition:
		all of them and
		androguard.package_name(/rkr.simplekeyboard.inputmethod/) or
		androguard.package_name(/com.shopiapps.roastcoffeetraders/) and
		androguard.app_name(/AVG AntiVirus 2020 for Android Security FREE/) and
		androguard.activity(/CryptoCipher/) and
		androguard.activity(/MraidActivity/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
		androguard.permission(/android.permission.BLUETOOTH/) and
		androguard.certificate.sha1("77452e18a9061094d214a06d9bce8407d01cb74b") and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
}
rule advservice_datacollection_detection_a
{
	meta:
		description =  "entifies this specific BadNews apk by the AdvService creation and information gathering by the use of variables."
		in_the_wild = True
	strings:
		$advservicelog_event = "AdvService started"
		$datavesn = "vesn"
		$datapacnme = "pacNme"
		$dataphMl = "phMl"
	condition:
		$advservicelog_event and $datavesn and $datapacnme and $dataphMl
}
rule koodous_zaa: official
{
	meta:
		description = "This rule detects SimpLocker"
		sample = "fd694cf5ca1dd4967ad6e8c67241114c"
	strings:
		$a = "http://xeyocsu7fu2vjhxs.onion/"
		$b = "19" 
		$c = "DISABLE_LOCKER"
		$d = "FILES_WAS_ENCRYPTED"
		$e = "127.0.0.1"
		$f = "jndlasf074hr" 
	condition:
		androguard.app_name(/SimpLocker/) and
		androguard.activity(/BOOT_COMPLETED/) and
		androguard.activity(/TOR_SERVICE/) and
		androguard.activity(/MainService$3/) and
		androguard.activity(/MainService$4/) and
		androguard.activity(/MainService$5/) and
		all of them and
		cuckoo.network.dns_lookup(/settings.crashlytics.com/) //Yes, we use crashlytics to debug our app!
}
rule Trojan_n: WipeLocker
{
	meta:
		description = "Trojan targeting external storage of android devices"
		sample = "f75678b7e7fa2ed0f0d2999800f2a6a66c717ef76b33a7432f1ca3435b4831e0"
	condition:
		androguard.package_name("com.elite") and
		androguard.app_name("Angry_BirdTransformers") and
		androguard.activity(/com.elite.MainActivity/i) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.permission(/android.permission.READ_CONTACTS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/)
}
rule CAJINO_a {
meta:
  author 		= "Matthijs en Nils"
  date 			= "10/11/2020"
  description 	= "This is a YARA rule for Cajino"
strings:
  $register = "getApplicationContext()"
  $phone 	= "getSystemService(\"phone\")"
  $feature1 = "getContact"
  $feature2 = "getCallLog"
  $feature3 = "getMessage"
  $feature4 = "getLocation"
  $feature5 = "sendTextMessage"
  $feature6 = "getPhoneInfo"
  $feature7 = "listFileByPath"
  $feature8 = "recorder.prepare()"
  $feature9 = "installApk"
condition:
  $register and $phone and 1 of ($feature*)
}
rule koodous_baaa: official
{
    meta:
		author = "Matthijs en Nils"
		date = "10/11/2020"
		description = "This is a YARA rule for Cyber Security APK 1"
    strings:
        $a = "http://www.whoishostingthis.com/tools/user-agent/"
        $b = "android.permission.GET_TASKS"
        $c = "android.permission.INTERNET"
        $d = "android.permission.WRITE_EXTERNAL_STORAGE"
        $e = "android.permission.READ_PHONE_STATE"
        $f = "android@android.com"
	 	$g = "note"
    condition:
        $a and $b and $c and $d and $e and $f and $g
}
rule fake_AVG_a {
    meta:
        description = "Detects a fake AVG Antivirus APK which contains adware."
        in_the_wild = true
    strings:
        $a = "https://mir-s3-cdn-cf.behance.net/project_modules/disp/3fd50115627063.562951a013590.jpg"
    condition:
        $a and
        androguard.app_name("AVG AntiVirus 2020 for Android Security FREE") and
        androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.CHANGE_WIFI_STATE/) and
        androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/) and
        androguard.certificate.sha1("6d0e7c4e30bfdb012bb6272a483434f60f41e7e0") and
        androguard.package_name("com.liudev.simplecakerecipes")
}
rule Cajino_h
{
	meta:
		Authors = "Teun de Mast and Lennard Hordijk"
		Studentnumbers = "respectively: 2656566 and 2716143"
		Description = "A rule to detect Cajino (remote controlled spyware)"
		Reference = "http://kharon.gforge.inria.fr/dataset/malware_Cajino.html"
	strings:
		$a = "com.baidu.android.pushservice.action.MESSAGE"
		$b = "com.baidu.android.pushservice.action.RECEIVE"
		$c = "com.baidu.android.pushservice.action.notification.CLICK"
		$d = "application/vnd.android.package-archive"
	condition:
		$a and $b and $c and $d
}
rule ransomware_j: svpeng android
{
	meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Ransomware"
		in_the_wild = true
	strings:
		$a =  {6e 64 20 79 6f 75 72 27 73 20 64 65 76 69 63 65 20 77 69 6c 6c 20 72 65 62 6f 6f 74 20 61 6e 64}
		$b = "ADD_DEVICE_ADMI"
	condition:
		$a and $b
}
rule Ransomware_d: banker android
{
	meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
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
rule koler_domains_c: android
{
	meta:
 		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
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
rule koler_builds_c: android
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Koler.A builds"
	strings:
		$0 = "buildid"
		$a = "DCEF055EEE3F76CABB27B3BD7233F6E3"
		$b = "C143D55D996634D1B761709372042474"
	condition:
		$0 and ($a or $b)
}
rule koler_class_c: android
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Koler.A class"
	strings:
		$0 = "FIND_VALID_DOMAIN"
		$a = "6589y459"
	condition:
		$0 and $a
}
rule koler_D_c: android
{
	meta:
		author = "https://twitter.com/jsmesa"
		reference = "https://koodous.com/"
		description = "Koler.D class"
	strings:
		$0 = "ZActivity"
		$a = "Lcom/android/zics/ZRuntimeInterface"
	condition:
		($0 and $a)
}

rule android_meterpreter_a
{
    meta:
        author="73mp74710n"
        ref = "https://github.com/zombieleet/yara-rules/blob/master/android_metasploit.yar"
        comment="Metasploit Android Meterpreter Payload"
    strings:
	$checkPK = "META-INF/PK"
	$checkHp = "[Hp^"
	$checkSdeEncode = /;.Sk/
	$stopEval = "eval"
	$stopBase64 = "base64_decode"
    condition:
	any of ($check*) or any of ($stop*)
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
rule silent_banker_o: banker
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
rule SMSSender_a
{
	meta:
		description = "This rule detects a type of SMSSender trojan"
		sample = "2b69cd97c90080dcdcd2f84ef0d91b1bfd858f8defd3b96fbcabad260f511fe7"
		search = "package_name:com.nys.mm"
	strings:
		$json_1 = "\"tn\":\"%s\",\"user\":\"%s\",\"locale\":\"%s\",\"terminal_version\":\"%s\",\"terminal_resolution\":\"%s\""
		$json_2 = "{\"v\":\"%s\",\"cmd\":\"sms\",\"params\":{\"first_pay_flag\":\"%s\",%s}}"
		$json_3 = "\"IsFetchSms\":\"1\",\"SoundTime\":\"10\",\"LbsTime\":\"3000\",\"SmsPattern\":"
		$fail_msg = "Fail to construct message"
		$code = "9AEKIJM?"
		$func_name = "setDiscount"
	condition:
		all of them
}

rule PornClicker_a
{
	meta:
		description = "It detects remote servers used in these trojans. Probably they are still at play store"
		sample = "https://www.virustotal.com/en/file/3f43f400f6014e0491f89e022f778358ba1d3ec717cd207b08e36255f323510e/analysis/1457541433/"
	strings:
		$a = "http://ultra16.eu"
		$b = "http://ultra17.eu"
		$c = "http://ultra18.eu"
		$d = "http://ultra19.eu"
		$e = "http://ultra20.eu"
		$f = "http://ultra3.lol"
		$g = "http://ultra4.lol"
		$h = "http://ultra6.lol"
		$i = "http://ultra7.lol"
		$j = "http://ultra8.lol"
		$k = "http://ultra11.lol"
		$l = "http://ultra12.lol"
		$m = "http://ultra13.lol"
		$n = "http://ultra14.lol"
		$o = "http://ultra15.lol"
		$p = "http://ultra1.xyz"
		$q = "http://ultra2.xyz"
		$r = "http://ultra4.xyz"
		$s = "http://ultra6.xyz"
		$t = "http://ultra7.xyz"
		$u = "http://ultra8.xyz"
		$v = "http://ultra9.xyz"
		$w = "http://ultra10.xyz"
		$x = "http://ultra11.xyz"
		$y = "http://ultra13.xyz"
		$z = "http://ultra14.xyz"
		$aa = "http://ultra16.xyz"
		$bb = "http://ultra17.xyz"
		$cc = "http://ultra18.xyz"
		$dd = "http://ultra19.xyz"
		$ee = "http://ultra20.xyz"
		$ff = "http://tranminhlaseriko.nailedporn.net"
		$gg = "http://tranminhlaseriko.milfsexhd.com"
		$hh = "http://www.ultrahdizle.com"
		$ii = "http://camlinhjaseriko.agonalia.com"
		$jj = "http://goptrecamut.dmba.us"
		$kk = "http://elm.eakalin.net"
		$ll = "http://goptrecamut.goglatube.com"
		$mm = "http://hatungrecasimpore.osmanlidasex.org"
		$nn = "http://vinhtoanrekozase.skyclocker.com"
		$oo = "http://wallpapers535.in"
		$pp = "http://derya.amateursexxe.com"
		$qq = "http://letrangzumkariza.pienadipiacere.mobi"
		$rr = "http://ngotrieuzalokari.sgcqzl.com"
		$ss = "http://hongvugarajume.pornsesso.net"
		$tt = "http://xuanchinhsalojare.italiano-films.net"
		$uu = "http://trucnhirezoka.kizsiktim.com"
		$vv = "http://w.bestmobile.mobi"
		$ww = "http://nguyendaozenrusa.sibelkekilii.com"
		$xx = "http://thuanzanposela.havuzp.net"
		$yy = "http://leminhzaderiko.osmanlipadisahlari.net"
		$zz = "http://palasandoreki.filmsme.net"
		$aaa = "http://art.hornymilfporna.com"
		$bbb = "http://cinar.pussyteenx.com"
		$ccc = "http://diyar.collegegirlteen.com"
		$ddd = "http://van.cowteen.com"
		$eee = "http://pop.oin.systems"
		$fff = "http://erfelek.coplugum.com"
		$ggg = "http://sptupumgoss.cosmicpornx.com"
		$hhh = "http://laserinozonre.dcambs.info"
		$jjj = "http://mecaguoolrean.xrabioso.com"
		$kkk = "http://merzifon.coplugum.com"
		$lll = "http://dkuraomtuna.hdfunysex.com"
		$mmm = "http://vuongdungjaseriko.passionne.mobi"
		$nnn = "http://ellroepzzmen.alohatubehd.com"
		$ooo = "http://thanhquocsocard.filmsts.net"
		$ppp = "http://cide.cncallgirls.com"
		$qqq = "http://tranminhlaseriko.nailedporn.net"
		$rrr = "http://ellroepzzmen.alohatubehd.com"
		$sss = "http://kendo.teenpornxx.com"
		$ttt = "http://lucasnguyenthe.viergeporn.com"
		$uuu = "http://trucnhirezoka.kizsiktim.com"
		$vvv = "http://kendo.teenpornxx.com"
		$www = "http://lh.oxti.org"
		$xxx = "http://bvn.bustech.com.tr"
		$yyy = "http://memr.oxti.org"
		$zzz = "http://juhaseryzome.orgasmhq.xyz"
		$aaaa = "http://posenryphamzi.pornnhd.xyz"
		$bbbb = "http://mawasenrikim.redtubexx.xyz"
		$cccc = "http://magarenikoperu.pornicom.xyz"
		$dddd = "http://magerinuzemu.youpornx.xyz"
		$eeee = "http://krn.dortuc.net"
		$ffff = "http://molletuome.21sextury.xyz"
		$gggg = "http://pemabetom.adulttpornx.com"
		$hhhh = "http://osman.dortucbilisim.org"
		$jjjj = "http://hanlienjawery.sexpornhq.xyz"
		$kkkk = "http://seyhan.mobileizle.com"
		$llll = "http://d.benapps3.xyz"
		$mmmm = "http://dwqs.xnxxtubes.net/"
	condition:
			any of them 
}
rule PornClickerAndro_a: Androguard {
	condition: 
	androguard.url("http://ultra16.eu") or androguard.url("http://ultra17.eu") or androguard.url("http://ultra18.eu") or androguard.url("http://ultra19.eu") or androguard.url("http://ultra20.eu") or androguard.url("http://ultra3.lol") or androguard.url("http://ultra4.lol") or androguard.url("http://ultra6.lol") or androguard.url("http://ultra7.lol") or androguard.url("http://ultra8.lol") or androguard.url("http://ultra11.lol") or androguard.url("http://ultra12.lol") or androguard.url("http://ultra13.lol") or androguard.url("http://ultra14.lol") or androguard.url("http://ultra15.lol") or androguard.url("http://ultra1.xyz") or androguard.url("http://ultra2.xyz") or androguard.url("http://ultra4.xyz") or androguard.url("http://ultra6.xyz") or androguard.url("http://ultra7.xyz") or androguard.url("http://ultra8.xyz") or androguard.url("http://ultra9.xyz") or androguard.url("http://ultra10.xyz") or androguard.url("http://ultra11.xyz") or androguard.url("http://ultra13.xyz") or androguard.url("http://ultra14.xyz") or androguard.url("http://ultra16.xyz") or androguard.url("http://ultra17.xyz") or androguard.url("http://ultra18.xyz") or androguard.url("http://ultra19.xyz") or androguard.url("http://ultra20.xyz") or androguard.url("http://tranminhlaseriko.nailedporn.net") or androguard.url("http://tranminhlaseriko.milfsexhd.com") or androguard.url("http://www.ultrahdizle.com") or androguard.url("http://camlinhjaseriko.agonalia.com") or androguard.url("http://goptrecamut.dmba.us") or androguard.url("http://elm.eakalin.net") or androguard.url("http://goptrecamut.goglatube.com") or androguard.url("http://hatungrecasimpore.osmanlidasex.org") or androguard.url("http://vinhtoanrekozase.skyclocker.com") or androguard.url("http://wallpapers535.in") or androguard.url("http://derya.amateursexxe.com") or androguard.url("http://letrangzumkariza.pienadipiacere.mobi") or androguard.url("http://ngotrieuzalokari.sgcqzl.com") or androguard.url("http://hongvugarajume.pornsesso.net") or androguard.url("http://xuanchinhsalojare.italiano-films.net") or androguard.url("http://trucnhirezoka.kizsiktim.com") or androguard.url("http://w.bestmobile.mobi") or androguard.url("http://nguyendaozenrusa.sibelkekilii.com") or androguard.url("http://thuanzanposela.havuzp.net") or androguard.url("http://leminhzaderiko.osmanlipadisahlari.net") or androguard.url("http://palasandoreki.filmsme.net") or androguard.url("http://art.hornymilfporna.com") or androguard.url("http://cinar.pussyteenx.com") or androguard.url("http://diyar.collegegirlteen.com") or androguard.url("http://van.cowteen.com") or androguard.url("http://pop.oin.systems") or androguard.url("http://erfelek.coplugum.com") or androguard.url("http://sptupumgoss.cosmicpornx.com") or androguard.url("http://laserinozonre.dcambs.info") or androguard.url("http://mecaguoolrean.xrabioso.com") or androguard.url("http://merzifon.coplugum.com") or androguard.url("http://dkuraomtuna.hdfunysex.com") or androguard.url("http://vuongdungjaseriko.passionne.mobi") or androguard.url("http://ellroepzzmen.alohatubehd.com") or androguard.url("http://thanhquocsocard.filmsts.net") or androguard.url("http://cide.cncallgirls.com") or androguard.url("http://tranminhlaseriko.nailedporn.net") or androguard.url("http://ellroepzzmen.alohatubehd.com") or androguard.url("http://kendo.teenpornxx.com") or androguard.url("http://lucasnguyenthe.viergeporn.com") or androguard.url("http://trucnhirezoka.kizsiktim.com") or androguard.url("http://kendo.teenpornxx.com") or androguard.url("http://lh.oxti.org") or androguard.url("http://bvn.bustech.com.tr") or androguard.url("http://memr.oxti.org") or androguard.url("http://juhaseryzome.orgasmhq.xyz") or androguard.url("http://posenryphamzi.pornnhd.xyz") or androguard.url("http://mawasenrikim.redtubexx.xyz") or androguard.url("http://magarenikoperu.pornicom.xyz") or androguard.url("http://magerinuzemu.youpornx.xyz") or androguard.url("http://krn.dortuc.net") or androguard.url("http://molletuome.21sextury.xyz") or androguard.url("http://pemabetom.adulttpornx.com") or androguard.url("http://osman.dortucbilisim.org") or androguard.url("http://hanlienjawery.sexpornhq.xyz") or androguard.url("http://seyhan.mobileizle.com") or androguard.url("http://d.benapps3.xyz") or androguard.url("http://tools.8782.net/stat.php?ac=uperr&did=%s&tg=%s&er=%s") or androguard.url("http://coco.zhxone.com/tools/datatools")
	}
rule PornClickerHTTP_a: Reequests {
	condition:
	cuckoo.network.http_request(/http:\/\/ultra16\.eu/) or cuckoo.network.http_request(/http:\/\/ultra17\.eu/) or cuckoo.network.http_request(/http:\/\/ultra18\.eu/) or cuckoo.network.http_request(/http:\/\/ultra19\.eu/) or cuckoo.network.http_request(/http:\/\/ultra20\.eu/) or cuckoo.network.http_request(/http:\/\/ultra3\.lol/) or cuckoo.network.http_request(/http:\/\/ultra4\.lol/) or cuckoo.network.http_request(/http:\/\/ultra6\.lol/) or cuckoo.network.http_request(/http:\/\/ultra7\.lol/) or cuckoo.network.http_request(/http:\/\/ultra8\.lol/) or cuckoo.network.http_request(/http:\/\/ultra11\.lol/) or cuckoo.network.http_request(/http:\/\/ultra12\.lol/) or cuckoo.network.http_request(/http:\/\/ultra13\.lol/) or cuckoo.network.http_request(/http:\/\/ultra14\.lol/) or cuckoo.network.http_request(/http:\/\/ultra15\.lol/) or cuckoo.network.http_request(/http:\/\/ultra1\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra2\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra4\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra6\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra7\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra8\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra9\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra10\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra11\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra13\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra14\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra16\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra17\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra18\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra19\.xyz/) or cuckoo.network.http_request(/http:\/\/ultra20\.xyz/) or cuckoo.network.http_request(/http:\/\/tranminhlaseriko\.nailedporn\.net/) or cuckoo.network.http_request(/http:\/\/tranminhlaseriko\.milfsexhd\.com/) or cuckoo.network.http_request(/http:\/\/www\.ultrahdizle\.com/) or cuckoo.network.http_request(/http:\/\/camlinhjaseriko\.agonalia\.com/) or cuckoo.network.http_request(/http:\/\/goptrecamut\.dmba\.us/) or cuckoo.network.http_request(/http:\/\/elm\.eakalin\.net/) or cuckoo.network.http_request(/http:\/\/goptrecamut\.goglatube\.com/) or cuckoo.network.http_request(/http:\/\/hatungrecasimpore\.osmanlidasex\.org/) or cuckoo.network.http_request(/http:\/\/vinhtoanrekozase\.skyclocker\.com/) or cuckoo.network.http_request(/http:\/\/wallpapers535\.in/) or cuckoo.network.http_request(/http:\/\/derya\.amateursexxe\.com/) or cuckoo.network.http_request(/http:\/\/letrangzumkariza\.pienadipiacere\.mobi/) or cuckoo.network.http_request(/http:\/\/ngotrieuzalokari\.sgcqzl\.com/) or cuckoo.network.http_request(/http:\/\/hongvugarajume\.pornsesso\.net/) or cuckoo.network.http_request(/http:\/\/xuanchinhsalojare\.italiano-films\.net/) or cuckoo.network.http_request(/http:\/\/trucnhirezoka\.kizsiktim\.com/) or cuckoo.network.http_request(/http:\/\/w\.bestmobile\.mobi/) or cuckoo.network.http_request(/http:\/\/nguyendaozenrusa\.sibelkekilii\.com/) or cuckoo.network.http_request(/http:\/\/thuanzanposela\.havuzp\.net/) or cuckoo.network.http_request(/http:\/\/leminhzaderiko\.osmanlipadisahlari\.net/) or cuckoo.network.http_request(/http:\/\/palasandoreki\.filmsme\.net/) or cuckoo.network.http_request(/http:\/\/art\.hornymilfporna\.com/) or cuckoo.network.http_request(/http:\/\/cinar\.pussyteenx\.com/) or cuckoo.network.http_request(/http:\/\/diyar\.collegegirlteen\.com/) or cuckoo.network.http_request(/http:\/\/van\.cowteen\.com/) or cuckoo.network.http_request(/http:\/\/pop\.oin\.systems/) or cuckoo.network.http_request(/http:\/\/erfelek\.coplugum\.com/) or cuckoo.network.http_request(/http:\/\/sptupumgoss\.cosmicpornx\.com/) or cuckoo.network.http_request(/http:\/\/laserinozonre\.dcambs\.info/) or cuckoo.network.http_request(/http:\/\/mecaguoolrean\.xrabioso\.com/) or cuckoo.network.http_request(/http:\/\/merzifon\.coplugum\.com/) or cuckoo.network.http_request(/http:\/\/dkuraomtuna\.hdfunysex\.com/) or cuckoo.network.http_request(/http:\/\/vuongdungjaseriko\.passionne\.mobi/) or cuckoo.network.http_request(/http:\/\/ellroepzzmen\.alohatubehd\.com/) or cuckoo.network.http_request(/http:\/\/thanhquocsocard\.filmsts\.net/) or cuckoo.network.http_request(/http:\/\/cide\.cncallgirls\.com/) or cuckoo.network.http_request(/http:\/\/tranminhlaseriko\.nailedporn\.net/) or cuckoo.network.http_request(/http:\/\/ellroepzzmen\.alohatubehd\.com/) or cuckoo.network.http_request(/http:\/\/kendo\.teenpornxx\.com/) or cuckoo.network.http_request(/http:\/\/lucasnguyenthe\.viergeporn\.com/) or cuckoo.network.http_request(/http:\/\/trucnhirezoka\.kizsiktim\.com/) or cuckoo.network.http_request(/http:\/\/kendo\.teenpornxx\.com/) or cuckoo.network.http_request(/http:\/\/lh\.oxti\.org/) or cuckoo.network.http_request(/http:\/\/bvn\.bustech\.com\.tr/) or cuckoo.network.http_request(/http:\/\/memr\.oxti\.org/) or cuckoo.network.http_request(/http:\/\/juhaseryzome\.orgasmhq\.xyz/) or cuckoo.network.http_request(/http:\/\/posenryphamzi\.pornnhd\.xyz/) or cuckoo.network.http_request(/http:\/\/mawasenrikim\.redtubexx\.xyz/) or cuckoo.network.http_request(/http:\/\/magarenikoperu\.pornicom\.xyz/) or cuckoo.network.http_request(/http:\/\/magerinuzemu\.youpornx\.xyz/) or cuckoo.network.http_request(/http:\/\/krn\.dortuc\.net/) or cuckoo.network.http_request(/http:\/\/molletuome\.21sextury\.xyz/) or cuckoo.network.http_request(/http:\/\/pemabetom\.adulttpornx\.com/) or cuckoo.network.http_request(/http:\/\/osman\.dortucbilisim\.org/) or cuckoo.network.http_request(/http:\/\/hanlienjawery\.sexpornhq\.xyz/) or cuckoo.network.http_request(/http:\/\/seyhan\.mobileizle\.com/) or cuckoo.network.http_request(/http:\/\/d\.benapps3\.xyz/)
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
rule SMSSender_b
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
rule koodous_caaa: official
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
	strings:
		$l = "dp.arm-v8.so.dat"
	condition:
		any of them
}
rule slempo_d: package
{
  meta:
    description = "This rule detects the slempo (slembunk) variant malwares by using package name and app name comparison"
    sample = "24c95bbafaccc6faa3813e9b7f28facba7445d64a9aa759d0a1f87aa252e8345"
  condition:
    androguard.package_name("org.slempo.service")
}
rule sandrorat_d
{
	meta:
		description = "This rule detects SandroRat samples"
	strings:
		$a = "SandroRat" 
	condition:
		$a
}
rule sandrorat_e
{
	meta:
		description = "This rule detects Sandrorat samples"
	strings:
		$a = "SandroRat"
	condition:
		$a		
}
rule sandrorat_f
{
	meta:
		description = "This rule detects SandroRat samples"
	strings:
		$a = "SandroRat"
	condition:
		$a
}
rule sandrorat_g
{
	meta:
		description = ""
	strings:
		$a = "sandrorat" nocase
	condition:
		$a
}
rule sandrorat_h
{
	meta:
		description = "This rule detects SandroRat samples"
	strings:
		$a = "sandrorat" nocase
	condition:
		$a
}
rule sandrorat_i
{
	meta:
		description = "Example"
	strings:
		$a = "Sandro"
	condition:
		$a
}
rule sandrorat_j
{
	meta:
		description = "This rule detects SandroRat samples"
	strings:
		$a = "sandrorat" nocase
	condition:
		$a
}
rule sandrorat_k
{
	meta:
		description = "This rule detects SandroRat samles"
	strings:
		$a = "SandroRat" nocase
	condition:
		$a
}
rule sandrorat_l
{
	meta:
		description="This rule detects SandroRat samples"
	strings:
		$a="SandroRat"
	condition:
		$a
}
rule prueba_a
{
meta: description = "Prueba"
strings:
$a = "giving me your money"
condition: $a
}
rule sandrorat_m
{
	meta:
		description = "This rule detects SandroRat samples"
	strings:
		$a = "SandroRat"
	condition:
		$a
}


