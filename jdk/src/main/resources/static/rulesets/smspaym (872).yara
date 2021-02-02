/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: SMSPaym
    Rule id: 872
    Created at: 2015-09-28 20:53:22
    Updated at: 2015-09-28 20:56:00
    
    Rating: #0
    Total detections: 136210
*/

import "androguard"


rule smsPaym
{
	meta:
		description = "AppSMSPayLog.aspx always returning true when no payment was done. Getting user to pay through SMS"


	strings:
		$a = "http://msg-web.pw:8456/msg/"
		// |ip----http://app.zjhyt.com/msg/||nimsi:|
		$b = "http://221.12.6.198:8010/APP/AppSMSPayLog.aspx"
		$c = "http://221.12.6.198:8010"
	condition:
		$a or $b or $c
		
		
		
}
