/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: lipizzan_1
    Rule id: 5080
    Created at: 2018-11-26 23:24:31
    Updated at: 2018-11-26 23:27:07
    
    Rating: #0
    Total detections: 289
*/

import "androguard"

rule lipizzan_1
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
