/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: GMBot Variant
    Rule id: 1967
    Created at: 2016-11-19 03:26:53
    Updated at: 2016-11-19 05:55:19
    
    Rating: #0
    Total detections: 137
*/

import "androguard"

rule Android_GMBot_Variant
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "08-November-2016"
		description = "This rule will be able to tag all GMBot variants."
		source = ""
	condition:
		androguard.service(/\.HeadlessSmsSendService/i) and
        androguard.receiver(/\.PushServiceRcvr/i) and
		androguard.receiver(/\.MmsRcvr/i) and
		androguard.receiver(/\.BootReceiver/i)
}
