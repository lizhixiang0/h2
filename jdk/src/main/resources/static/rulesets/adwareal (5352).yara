/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: AdwareAL
    Rule id: 5352
    Created at: 2019-03-12 00:28:30
    Updated at: 2019-03-14 00:02:10
    
    Rating: #0
    Total detections: 19
*/

import "androguard"
import "file"
import "cuckoo"


rule AdwareAL
{
	meta:
		description = "Android Adware"
		md5 = "057eb20bab154b67f0640bc48e3db59a"
		
		
	strings:
		$a_1 = "rebrand.ly" fullword
		$a_2 = "setAdUnitId" fullword
		$a_3 = "loadAd" fullword
		$a_4 = "AdActivity" fullword



	
	condition:
		all of ($a_*)
 			    
				
}
