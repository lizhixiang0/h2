/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: PornApps
    Rule id: 1469
    Created at: 2016-06-03 20:39:19
    Updated at: 2017-01-18 01:30:26
    
    Rating: #0
    Total detections: 4909
*/

import "androguard"
import "file"
import "cuckoo"


rule PornApps
{
	meta:
		description = "Rule to detect certain Porn related apps"
		sample = "baea1377a3d6ea1800a0482c4c0c4d8cf50d22408dcf4694796ddab9b011ea14"
		
	strings:
		$a = "/system/bin/vold"
	
			
	condition:
		(androguard.activity(/.HejuActivity/) and $a)or
		androguard.service(/\.cn\.soor\.qlqz\.bfmxaw\.a\.a\.c\.d/)
}
