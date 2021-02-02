/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: albertosegura
    Rule name: SMSSpyTrojan
    Rule id: 4904
    Created at: 2018-09-26 13:37:45
    Updated at: 2018-09-26 13:46:47
    
    Rating: #0
    Total detections: 12
*/

import "androguard"
import "file"
import "cuckoo"


rule Trojan : SMSSpy
{
	meta:
		description = "This rule detects the dropper of a trojan that steal SMS"
		sample = "c2b672fdde5e141b8db513a30b8254b9434f0eef4f0c92a55988347a20934206"

	strings:
		$trojanapp = "android.system.apk"
		$trojanservice = "com.android.system.MyService"

	condition:
		// androguard.package_name("com.android.app") and 
		$trojanapp and
		$trojanservice
}
