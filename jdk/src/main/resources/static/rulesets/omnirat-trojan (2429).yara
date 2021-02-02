/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mwhunter
    Rule name: OmniRAT Trojan
    Rule id: 2429
    Created at: 2017-04-06 14:44:07
    Updated at: 2017-04-06 14:58:33
    
    Rating: #0
    Total detections: 14
*/

import "androguard"
import "file"
import "cuckoo"


rule OmniRAT : RAT
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
