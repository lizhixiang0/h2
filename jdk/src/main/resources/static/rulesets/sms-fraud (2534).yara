/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: SMS Fraud
    Rule id: 2534
    Created at: 2017-04-23 02:25:35
    Updated at: 2017-04-23 02:35:49
    
    Rating: #0
    Total detections: 5457
*/

import "androguard"

rule SMS_Fraud
{
	meta:
		Author = "https://www.twitter.com/SadFud75"
	condition:
		androguard.package_name("com.sms.tract") or androguard.package_name("com.system.sms.demo") or androguard.package_name(/com\.maopake/)
}
