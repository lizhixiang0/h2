/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: baal
    Rule name: Android.Lockscreen
    Rule id: 1847
    Created at: 2016-09-28 08:38:26
    Updated at: 2016-09-28 08:41:37
    
    Rating: #0
    Total detections: 2444
*/

import "androguard"



rule Lockscreen : malware
{
	meta:
		description = "https://www.symantec.com/security_response/writeup.jsp?docid=2015-032409-0743-99&tabid=2"


	condition:
		
		androguard.service(/lockphone.killserve/i) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		androguard.filter(/android.intent.action.BOOT_COMPLETED/)
		
	
}
