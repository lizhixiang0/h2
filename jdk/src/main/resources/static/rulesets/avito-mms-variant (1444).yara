/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: AVITO-MMS Variant
    Rule id: 1444
    Created at: 2016-05-28 03:19:39
    Updated at: 2016-07-02 04:09:36
    
    Rating: #0
    Total detections: 176
*/

import "androguard"

rule Android_AVITOMMS_Variant
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

rule Android_AVITOMMS_Rule2
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
