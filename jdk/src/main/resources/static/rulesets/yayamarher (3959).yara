/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaMarher
    Rule id: 3959
    Created at: 2018-01-05 11:27:46
    Updated at: 2018-01-05 11:40:02
    
    Rating: #0
    Total detections: 6
*/

import "androguard"
import "cuckoo"


rule YaYaMarcher: ruleDef {
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
