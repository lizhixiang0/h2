/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: YaYaGen
    Rule name: Banker rule
    Rule id: 4911
    Created at: 2018-09-27 12:08:25
    Updated at: 2018-09-27 12:08:39
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "cuckoo"


rule YaYa: rule0 {
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
