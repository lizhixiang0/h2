/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Gaurav
    Rule name: Backdoor_script
    Rule id: 1872
    Created at: 2016-10-04 11:51:28
    Updated at: 2016-10-17 18:47:39
    
    Rating: #1
    Total detections: 180
*/

import "androguard"


rule koodous : official
{
	meta:
		description = "Detects samples repackaged by backdoor-apk shell script"
		Reference = "https://github.com/dana-at-cp/backdoor-apk"
		
	strings:
		$str_1 = "cnlybnq.qrk" // encrypted string "payload.dex"

	condition:
		$str_1 and 
		androguard.receiver(/\.AppBoot$/)		
}
