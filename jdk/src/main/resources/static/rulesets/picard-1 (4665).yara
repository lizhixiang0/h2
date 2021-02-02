/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dgarcia
    Rule name: Picard-1
    Rule id: 4665
    Created at: 2018-07-18 11:10:40
    Updated at: 2018-07-18 11:10:44
    
    Rating: #0
    Total detections: 143
*/

import "androguard"


 rule ruleNumber1{
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
