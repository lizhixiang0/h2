/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: chased
    Rule name: New Ruleset
    Rule id: 5886
    Created at: 2019-09-09 08:16:31
    Updated at: 2019-09-09 09:56:29
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule Trojan : apt36
{
	meta:
        description = "Trojan targeting Banks with Overlays"
		source = ""
	
	strings:
		$c2_1 = "ColoRich" nocase
		$c2_2 = "taothao" nocase
		$c2_3 = "tran hien" nocase
		$c2_4 = "taothao2012@gmail.com" nocase
		$c2_5 = "alexhien.com@gmail.com" nocase
		
	condition:
		1 of ($c2_*)
		and (
			androguard.permission(/android.permission.RECEIVE_SMS/) 
			or androguard.permission(/android.permission.READ_SMS/)
		)
}
