/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: reddit_adware
    Rule id: 5376
    Created at: 2019-03-27 01:53:31
    Updated at: 2019-03-27 02:12:22
    
    Rating: #1
    Total detections: 7
*/

import "androguard"
import "file"
import "cuckoo"


rule reddit_adware
{
	meta:
		description = "Reddit adware"
		sha = "1dfa6b8267733667d1a6b838c235e10146ae33e708a2755240947b8047bcc39f"
		
		
	strings:
        $a_1 = "Telephony SECRET_CODE" fullword
        $a_2 = "Ti92T_77Zij_MiTik" fullword
        $a_3 = "SendTaskInfo1 content" fullword
	
	condition:
		all of ($a_*)
		
}
