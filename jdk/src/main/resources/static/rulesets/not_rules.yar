

rule joker_camera: official
{
	condition:
		(androguard.app_name(/camera/) or
		androguard.app_name(/wallpaper/) or
		androguard.app_name(/game/)) and
		androguard.permission(/PHONE_STATE/) and
		androguard.permission(/CHANGE_WIFI_STATE/)
}

rule PimentoRoot: rootkit
{
	condition:
		androguard.url(/http:\/\/webserver\.onekeyrom\.com\/GetJson\.aspx/)
}

rule FakeSpy
 {
   strings:
      $a = "AndroidManifest.xml"
      $b = "lib/armeabi/librig.so"
      $c = "lib/armeabi-v7a/librig.so"
   condition:
      $a and ($b or $c) and (filesize > 2MB and filesize < 3MB)
}

rule Android_Trojan_Ransomware_Coin
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

rule PUA: Untrusted_Cert
{
    condition:
        androguard.certificate.sha1("7E1119BBD05DE6D0CBCFDC298CD282984D4D5CE6") or
       	androguard.certificate.sha1("DEF68058274368D8F3487B2028E4A526E70E459E")
}

rule Suspect
{
	strings:
		$ = "tppy.ynrlzy.cn"
	condition:
		1 of them
}

rule guitarsupersolo
{
        meta:
            desc = "YARA Rule to detect suspicious activity"
        strings:
            $a = "rooter"
            $b = "0x992c35d3"
        condition:
            $a and $b
    }

rule fake_facebook: fake android
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Facebook")
		and not androguard.certificate.sha1("A0E980408030C669BCEB38FEFEC9527BE6C3DDD0")
}

rule fake_instagram: fake android
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("Instagram")
		and not androguard.certificate.sha1("76D72C35164513A4A7EBA098ACCB2B22D2229CBE")
}

rule fake_king_games: fake android
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

rule fake_market: fake android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		androguard.package_name("com.minitorrent.kimill")
}

rule fake_minecraft: fake android
{
  meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
	condition:
		( androguard.app_name("Minecraft: Pocket Edition") or
			androguard.app_name("Minecraft - Pocket Edition") )
		and not androguard.package_name("com.mojang.minecraftpe")
}

rule fake_whatsapp: fake android
{
  meta:
		  author = "https://twitter.com/Diviei"
		  reference = "https://koodous.com/"
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}

rule fakeinstaller_sms
{
	strings:
		$a = "http://sms24.me" wide
		$b = "http://sms911.ru" wide
		$c = "smsdostup.ru" wide
	condition:
		any of them
}

rule Trojan_Droidjack
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

rule GhostFrameWork_EventDex
{
	strings:
		$a = "EventDex"
	condition:
		$a
}

rule fanghu: official
{
	condition:
		androguard.app_name("fanghu")
}

rule credicorp
{
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

rule WhatsApp: Virus
{
	condition:
	   androguard.url("google.com/iidKZ.KxZ/=-Z[")
}

rule riltok_koo
{
    strings:
        $s1 = "librealtalk-jni.so"
        $s2 = "AmericanExpress"
        $s3 = "cziugqk"
    condition:
        all of them
}

rule da: official
{
	strings:
		$MD5 = "8037c51ababaaeb8da4d8a0b460223a2"
		$SHA1 = "b657d2817ff6d511d6c2b725c58180721d1e153c"
		$AppName = "Hediye Kutusu"
		$Developer = "Hediye Fun Corp."
	condition:
		$MD5 or $SHA1 or $AppName or $Developer
}

rule ea: official
{
	strings:
		$MD5 = "5f08fb3e2fc00391561578d0e5142ecd"
		$SHA1 = "db35baeb9fc92ea28b116ec7da02af1cd0797dcf"
		$AppName = "Viber"
		$Developer = "UMT inc."
	condition:
		$MD5 or $SHA1 or $AppName or $Developer
}

rule dowgin:adware android
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

rule russian_domain: adware
{
	strings:
		$a = "zzwx.ru"
	condition:
		$a
}

rule LokiBotMobile
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

rule LokiBotMobile1
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

rule readAlertNEW
{
	strings:
		$string_1 = "twwitter.com"
		$string_2 = /http:\/\/\S+:7878/
		$string_4 = "utc/now?%5CD"
	condition:
		all of ($string_*)
}

rule Pakistan
{
 strings:
   $a1 = "com.avanza.ambitwiz" wide ascii
 condition:
   $a1
}

rule Coinhive4
{
 strings:
   $a1 = "CoinHiveIntentService" wide ascii
   $a2 = "com.kaching.kingforaday.service.CoinHiveIntentService" wide ascii
 condition:
   any of them
}

rule RuClicker
{
	strings:
		$ = "CiLscoffBa"
		$ = "FhLpinkJs"
		$ = "ZhGsharecropperFx"
	condition:
 		all of them
}

rule LeakerLocker2
{
	condition:
		androguard.service(/x\.u\.s/)
}

rule com_house_crust
{
		strings:
			$a = "assets/com.jiahe.school.apk" nocase
		condition:
		androguard.package_name("com.house.crust") or
		androguard.certificate.sha1("E1DF7A92CE98DC2322C7090F792818F785441416") and
		$a
}

rule la: official
{
	strings:
		$a = "your files have been encrypted!"
		$b = "your Device has been locked"
		$c = "All information listed below successfully uploaded on the FBI Cyber Crime Depar"
	condition:
		$a or $b or $c or androguard.package_name("com.android.admin.huanmie") or androguard.package_name("com.android.admin.huanmie")
}

rule rest
{
	strings:
		$ = "cards, you can resolve the confusion within your heart. Every card has two"
	  	$ = "sides, representing the Pros and Cons of a subject. All the answers are"
		$ = "First of all, this is a free software, but due to the high development costs"
	condition:
		all of them
}

rule Trojan_Banker4:Marcher
{
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

rule Target_Instagram: official
{
	strings:
		$string_target_fbmessenger = "com.instagram.android"
	condition:
	($string_target_fbmessenger)
}

rule users_location
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

rule get_deviceId
{
	strings:
		$string2 = "getdeviceId"
		$string3 = "android/telephony/TelephonyManager"
	condition:
		$string2 and $string3
}

rule faa: official
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

rule commasterclean
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

rule CleanupRadar
{
	condition:
	androguard.package_name("com.Airie.CleanupRadar")
}

rule BankBot_b
{
	strings:
		$a = "/private/tuk_tuk.php"
		$b = "/set/tsp_tsp.php"
	condition:
		$a or $b
}

rule certs
{
	condition:
		androguard.certificate.sha1("3F65615D7151BA782F9C0938B01F4834B8E492BC") or
		androguard.certificate.sha1("AFD2E81E03F509B7898BFC3C2C496C6B98715C58") or
		androguard.certificate.sha1("E6D2E5D8CCBB5550E666756C804CA7F19A523523") or
		androguard.certificate.sha1("7C9331A5FE26D7B2B74C4FB1ECDAF570EFBD163C")          // Ransomware Locker
}

rule FakePostBank_b
{
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

rule pokemon
{
	condition:
		androguard.app_name(/pokemongo/i)
}

rule adware
{
    condition:
		androguard.filter("com.airpush.android.DeliveryReceiver") or
		androguard.filter(/smsreceiver/)
}

rule downloader:trojan
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

rule SMS_Fraud
{
	meta:
		Author = "https://www.twitter.com/SadFud75"
	condition:
		androguard.package_name("com.sms.tract") or androguard.package_name("com.system.sms.demo") or androguard.package_name(/com\.maopake/)
}

rule Fake_Hill_Climb2
{
  meta:
      Author = "https://twitter.com/SadFud75"
      Info = "Detection of fake hill climb racing 2 apps"
  condition:
      androguard.app_name("Hill Climb Racing 2") and not androguard.certificate.sha1("F0FDF0136D03383BA4B2BE81A14CD4B778FB1F6C")
}

rule Trojan_Androrat
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

rule Metasploit_Payload
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

rule wefleet
{
	strings:
		$a = "wefleet.net/smstracker/ads.php" nocase
	condition:
		$a
}

rule Banker_Acecard
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

rule marcher2
{
	strings:
		$a = "HDNRQ2gOlm"
		$b = "lElvyohc9Y1X+nzVUEjW8W3SbUA"
	condition:
		all of them
}

rule marcher3
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

rule Banker1
{
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

rule Banker2
{
	strings:
		$ = "85.93.5.228/index.php?action=command"
		$ = "email@fgdf.er"
		$ = "majskdd@ffsa.com"
		$ = "185.48.56.10"
	condition:
		1 of them
}

rule Banker3
{
	strings:
	$ = "cosmetiq/fl/service" nocase
	condition:
	1 of them
}

rule ibers
{
  strings:
	$string_1 = /scottishpower\.com/
	$string_2 = /avangrid\.com/
	$string_3 = /neoenergia\.com/
	$string_4 = /iberdrola/
  condition:
	any of them
}

rule lokibot_old
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

rule Click415to417
{
	strings:
	 $ = "http://apk-archive.ru"
	 $ = "aHR0cDovL2Fway1hcmNoaXZlLnJ1L2dvb2dsZXBsYXlhcHBzL2NoZWNrL281L2luZGV4LnBocD9pbXNpPQ"
	condition:
		androguard.url(/apk-archive.ru/i)
		or
		1 of them
}

rule Title_Santander
{
	strings:
		$string_1 = /Santander/
		$string_2 = /Spendlytics/
		$string_3 = /SmartBank/
		$string_4 = /Flite/
	condition:
	4 of ($string_*)
}

rule Coinhive
{
 strings:
   $a1 = "*rcyclmnrepv*" wide ascii
   $a2 = "*coin-hive*" wide ascii
   $a3 = "*coin-hive.com*" wide ascii
   $a4 = "*com.android.good.miner*" wide ascii
 condition:
   any of them
}

rule

rule crypto_b: jcarneiro
{
	strings:
		$a = "pool.minexmr.com"
	condition:
		$a
}

rule edvo
{
	strings:
		$a= "EDVO revision 0"
	condition:
		all of them
}

rule plantsvszombies:SMSFraud
{
	meta:
		sample = "ebc32e29ceb1aba957e2ad09a190de152b8b6e0f9a3ecb7394b3119c81deb4f3"
	condition:
		androguard.certificate.sha1("2846AFB58C14754206E357994801C41A19B27759")
}

rule SMSFraud
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

rule fraudulent:numeric_developers
{
	meta:
		search = "developer:91"
		search2 = "developer:86"
		search3 = "developer:34"
	condition:
		androguard.certificate.sha1("7D4EA444984A1AD84BBE408DB4A57A42B989E51A") or //developer 91
		androguard.certificate.sha1("78739E2E80F74715D31A72185942487216E40D81") or //developer 86
		androguard.certificate.sha1("E08260D36C0E5E2CEB9DE2FB0BAB0ABEA1471058") //developer 34
}

rule genericSMS: smsFraud
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

rule genericSMS2: smsFraud
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

rule genericSMS3: smsFraud
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

rule SMSsend
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

rule Twittre
{
    condition:
        androguard.certificate.sha1("CEEF7C87AA109CB678FBAE9CB22509BD7663CB6E") and not
		androguard.certificate.sha1("40F3166BB567D3144BCA7DA466BB948B782270EA") //original
}

rule dropper_c
{
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

rule unknown
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

rule Sparkasse: Fake Banking App
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

rule Postbank: Fake Banking App
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

rule Volksbank: Fake Banking App
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

rule Commerzbank: Fake Banking App
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

rule DKBpushTAN: Fake Banking App
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

rule experimental
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

rule HiddenApp
{
	strings:
	  	$ = /ssd3000.top/
		$ = "com.app.htmljavajets.ABKYkDEkBd"
	condition:
		1 of them
}

rule OtakuVideo: chinese_porn
{
	meta:
		sample = "449a9fc0694b483a4c1935b33eea433268560784d819f0d63bf66080f5529df8"
	condition:
		cuckoo.network.dns_lookup(/api\.hykuu\.com/) or
		cuckoo.network.dns_lookup(/wo\.ameqq\.com/) or
		cuckoo.network.dns_lookup(/home\.qidewang\.com/) or
		cuckoo.network.dns_lookup(/img\.gdhjkm\.com/) or
		androguard.certificate.sha1("42867A29DCD05B048DBB5C582F39F8612A2E21CD")
}

rule AiQingYingShi: chinese_porn
{
	condition:
        androguard.app_name(/\xe7\x88\xb1\xe6\x83\x85[\w]+?\xe5\xbd\xb1\xe8\xa7\x86[\w]{,11}/) or
        androguard.app_name("\xe7\xa6\x81\xe6\x92\xad\xe8\xa7\x86\xe9\xa2\x91") or
        androguard.package_name("com.tzi.shy") or
        androguard.package_name("com.shenqi.video.nfkw.neim") or
        androguard.package_name("com.tos.plabe") or
        cuckoo.network.http_request(/www\.sexavyy\.com:8088/) or
        cuckoo.network.http_request(/spimg\.ananyy\.com/)
}

rule Trojan_Banker:Marcher
{
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

rule Trojan_SberBank:Generic
{
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

rule fakeinstaller
{
	meta:
		sample = "e39632cd9df93effd50a8551952a627c251bbf4307a59a69ba9076842869c63a"
	condition:
		androguard.permission(/com.android.launcher.permission.INSTALL_SHORTCUT/)
		and androguard.permission(/android.permission.SEND_SMS/)
		and androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")
		and androguard.certificate.issuer(/hghjg/)
}

rule Rana_Android_resources
{
    strings:
        $res1 = "res/raw/cng.cn" fullword wide ascii
        $res2 = "res/raw/att.cn" fullword wide ascii
        $res3 = "res/raw/odr.od" fullword wide ascii
    condition:
        any of them
}

rule sushinow
{
    strings:
        $launcher_image = "EA DB A8 44 25 9A 27 93 8A 25 D2 E0 A2 42 8B D6 F8 10 11 F2 C4 5D 10 D2 8B FA D5 8C DC 5E 85 FA F5 E3 90 9F 23 1B DB BE 45 AC B2 86 0D 19 33 CB 5F 1F A9 0A 45 A3 40 E4 AC 3C 58 58 7D A6 F7 DB B9 00 20 A4 8D 82 B3 60 3A EA 4E 32 43 DB B7 8A A9 3E 8E 58 58 22 05 88 6C 9F 2F 7A 24 91 CC B1 2A 40 CE 82 19 F1 6B 2B 3F 18 66 B4 4E 4E 74 FB 56 31 49 24 73 B6 CF 17 3D 91 42 14 31 40 E3 8B C8 4F AD 3C 0F 15 B3 27 C6 B1 AD 49 5D BF 87 9C 9C E8 F6 AD 64 AA AF E3 06 10 59 70 BF E0 74 48 64 9E 95 01 E2 9C F9 F1 6B CB 55 D8 ED EF BA 93 2C E1 ED 5B C9 1C 12 99 B7 E0 7E C1 19 09 44 11 01 74 CB 95 DC 95 48 26 63 D4 F0 F6 AD 06 91 EA"
        $app_id = "013df7ae-6c39-4a9e-9151-fd626d536dcc"
        $app_server = "EhUbWAcbLRoGAD5FHQAJ"
    condition:
        $launcher_image or $app_id or $app_server
}

rule security: Google Chrome
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

rule smsfraud_c
{
	meta:
		sample = "7ea9a489080fa667b90fb454b86589ac8b018c310699169b615aabd5a0f066a8"
		search = "cert:14872DA007AA49E5A17BE6827FD1EB5AC6B52795"
	condition:
		androguard.certificate.sha1("14872DA007AA49E5A17BE6827FD1EB5AC6B52795")
}

rule smsfraud2
{
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

rule malicious_certs
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

rule koodousjaaaaa: official
{
	condition:
		androguard.service("com.shunwang.service.CoreService")
}

rule sdks
{
	condition:
		androguard.app_name(/bank/)
}

rule sec: v1
{
	condition:
		androguard.package_name(/seC./)
}

rule findbutton
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

rule SeSeAOV: SexApp
{
	meta:
		sample = "f93222a685f45487732e1692d6c1cbeb3748997c28ca5d61c587b21259791599"
	condition:
		cuckoo.network.dns_lookup(/h.\.tt-hongkong.com/)
}

rule mobby
{
	strings:
		$a = "io/mobby/sdk/receiver"
		$b = "io/mobby/sdk/activity"
		$c = "mobby"
	condition:
		any of them
}

rule koodoustaaaaa: official
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

rule ransomware_generic
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

rule xmrigStrings
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

rule WireX
{
	strings:
		$ = "g.axclick.store"
		$ = "ybosrcqo.us"
		$ = "u.axclick.store"
    	$ = "p.axclick.store"
	condition:
		1 of them
}

rule KikDroid
{
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

rule Test7
{
	condition:
		androguard.package_name("com.estrongs.android.pop")
}

rule svpeng2
{
	strings:
		$= "http://217.182.174.92/jack.zip"
	condition:
		all of them
}

rule android_tempting_cedar_spyware
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

rule appsix
{
    strings:
		$a1 = "cvc_visa"
		$a2 = "controller.php"
		$a3 = "mastercard"
	condition:
        androguard.package_name(/app.six/) and
		2 of ($a*)
}

rule weixin: fakeapp
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

rule yundong_24xia: fakeapp
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

rule koodousda: skymobi
{
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$a = "Java_com_skymobi_pay_common_util_LocalDataDecrpty_Decrypt"
		$b = "Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt"
	condition:
		all of them
}

rule Trojan_BankBot_7878
{
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

rule VT_Sonicspy: Spy
{
	meta:
		detail = "https://blog.lookout.com/sonicspy-spyware-threat-technical-research"
	strings:
		$ = "dt7C1uP3c2al6l0ib"
		$ = "not concteed"
	condition:
		all of them
}

rule Leecher_A
{
    condition:
        androguard.certificate.sha1("B24C060D41260C0C563FEAC28E6CA1874A14B192")
}

rule Service:Gogle
{
	condition:
		androguard.service("com.module.yqural.gogle")
}

rule Banker2_c
{
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

rule Trojan_SMS:Banker
{
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

rule koodousja: official
{
	condition:
		androguard.certificate.sha1("74D37EED750DBA0D962B809A7A2F682C0FB0D4A5")
}

rule smssender_FakeAPP
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

rule Downloader_b
{
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

rule simple

rule Cajino_c
{
    meta:
        Description = "This is a basic YARA rule "
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

rule chineseSMSSender
{
	condition:
		androguard.package_name("com.android.phonemanager") and
		androguard.permission(/android.permission.SEND_SMS/)
}

rule dropper_f:realshell
{
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		$b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
	condition:
		$b
}

rule chineseporn5: SMSSend
{
	condition:
		androguard.package_name("com.shenqi.video.ycef.svcr") or
		androguard.package_name("dxas.ixa.xvcekbxy") or
		androguard.package_name("com.video.ui") or
		androguard.package_name("com.qq.navideo") or
		androguard.package_name("com.android.sxye.wwwl") or
		androguard.certificate.issuer(/llfovtfttfldddcffffhhh/) or
		androguard.activity(/com\.shenqi\.video\.Welcome/) or
        androguard.package_name("org.mygson.videoa.zw")
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

rule londatiga
{
	condition:
		androguard.certificate.sha1("ECE521E38C5E9CBEA53503EAEF1A6DDD204583FA")
}

rule minecraft
{
	condition:
		( androguard.app_name("Minecraft: Pocket Edition") or
			androguard.app_name("Minecraft - Pocket Edition") )
		and not androguard.package_name("com.mojang.minecraftpe")
}

rule hostingmy
{
	condition:
		androguard.certificate.issuer(/hostingmy0@gmail.com/)
}

rule Chrome: fake
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

rule Discord: fake
{
	condition:
		(
		androguard.app_name(/^D[il1]sc[o0]rd$/i) or
		androguard.package_name(/com.discord/)
		) and not (
		androguard.certificate.sha1("B07FC6AECCD21FCBD40543C85112CAFE099BA56F")
		)
}

rule Facebook: fake
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

rule Facebook_Lite: fake
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

rule Google_Apps: fake
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

rule Instagram: fake
{
	condition:
		(
		androguard.app_name(/^[Il1]nstagram$/i) or
		androguard.package_name(/com.instagram/)
		) and not (
		androguard.certificate.sha1("C56FB7D591BA6704DF047FD98F535372FEA00211")
		)
}

rule Telegram: fake
{
	condition:
	(
	androguard.app_name(/^Telegram$/i) or
	androguard.package_name(/org.telegram.messenger/)
	) and not (
	androguard.certificate.sha1("9723E5838612E9C7C08CA2C6573B6026D7A51F8F")
	)
}

rule Twitter: fake
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

rule BeiTaPlugin
{
	strings:
		$a1 = "assets/beita.renc"
		$a2 = "assets/icon-icomoon-gemini.renc"
		$a3 = "assets/icon-icomoon-robin.renc"
		$b = "Yaxiang Robin High"   // Decryption key
	condition:
		any of them// and
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

rule rootnik2: sites2
{
	strings:
	 $a = "aHR0cDovL2Nkbi5hcHBsaWdodC5tb2JpL2FwcGxpZ2h0LzIwMTUvMTQ0MjgyNDQ2MnJlcy5iaW4=" // base 64 encoded: /http:\/\/cdn.applight.mobi\/applight\/2015\/1442824462res.bin/
	condition:
		 cuckoo.network.http_request(/http:\/\/api.jaxfire\.mobi\/app\/getTabsResBin/) and (cuckoo.network.http_request(/http:\/\/cdn.applight.mobi\/applight\/2015\/1442824462res.bin/) or $a)
}

rule rootnik3: string
{
	strings:
	$a = "http://api.shenmeapp.info/info/report"
	condition:
	$a or (androguard.url(/applight\.mobi/) and androguard.url(/jaxfire\.mobi/))
}

rule rooting
 {
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

rule random: adware
{
    strings:
        $a = /cellphone-tips\.com/
    condition:
        androguard.url(/cellphone-tips\.com/) or
		$a
}

rule Agent_Smith
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

rule anubisNew_July2019
 {
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

rule Samsung: Chrysaor
{
    strings:
        $a = "ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5"
	condition:
		androguard.package_name("com.network.android") and
		$a
}

rule anubis3: Dropper
{
	condition:
	  androguard.permission(/READ_EXTERNAL_STORAGE/) and
	  androguard.permission(/RECEIVE_BOOT_COMPLETED/) and
	  androguard.permission(/REQUEST_INSTALL_PACKAGES/) and
	  androguard.permission(/INTERNET/) and
	  androguard.permission(/WRITE_EXTERNAL_STORAGE/) and
	  androguard.permissions_number < 10
}

rule GGTRACK_detecrot: trojan
{
	condition:
		androguard.url("http://ggtrack.org/") or
		androguard.url(/ggtrack\.org/)
}

rule smsfraud2_b
{
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

rule Hack_game_candy
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

rule Shedun
{
	strings:
		$a = "hehe you never know what happened!!!!"
		$b = "madana!!!!!!!!!"
	condition:
 		all of them
}
