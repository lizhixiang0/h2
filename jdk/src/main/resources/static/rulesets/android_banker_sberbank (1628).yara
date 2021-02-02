/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: Android_Banker_Sberbank
    Rule id: 1628
    Created at: 2016-07-14 12:52:46
    Updated at: 2016-07-14 12:57:04
    
    Rating: #1
    Total detections: 104
*/

import "androguard"

rule Android_Banker_Sberbank
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android Banker Sberbank"
		source = "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"

	condition:
		androguard.service(/MasterInterceptor/i) and 
		androguard.receiver(/MasterBoot/i) and 
		androguard.filter(/ACTION_POWER_DISCONNECTED/i)
}
