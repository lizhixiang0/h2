/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: anand
    Rule name: New Ruleset
    Rule id: 5489
    Created at: 2019-04-24 10:04:59
    Updated at: 2019-04-24 10:05:21
    
    Rating: #0
    Total detections: 1
*/

import "androguard"
import "file"
import "cuckoo"


rule Android_Trojan_FakeAd_B
{
	meta:
		description = "Rule used to detect jio and paytm fakeapp"
		source = "Lastline"
		Author = "Anand Singh"
		Date = "24/04/2019"
	
	strings:
		$a1 = "JIO NUMBER[local]"
		$a2 = "JioWebService/rest"
		$a3 = "WhatsApp not Installed"
		$a4 = "Congratulations!!"
		
		$b = "Lme/zhanghai/android/materialprogressbar/"

	condition:
		2 of ($a*) and $b
}
