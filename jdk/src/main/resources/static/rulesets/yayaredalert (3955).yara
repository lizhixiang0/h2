/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: YaYaRedAlert
    Rule id: 3955
    Created at: 2018-01-04 16:58:19
    Updated at: 2018-01-04 16:58:30
    
    Rating: #0
    Total detections: 20
*/

import "androguard"
import "cuckoo"


rule YaYaRedAlert: rule0 {
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
