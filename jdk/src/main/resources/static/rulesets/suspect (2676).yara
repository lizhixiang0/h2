/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Suspect
    Rule id: 2676
    Created at: 2017-05-10 13:41:06
    Updated at: 2017-05-29 11:00:39
    
    Rating: #0
    Total detections: 11603
*/

import "androguard"

rule PUA: Untrusted_Cert
{
    condition:
        androguard.certificate.sha1("7E1119BBD05DE6D0CBCFDC298CD282984D4D5CE6") or
       	androguard.certificate.sha1("DEF68058274368D8F3487B2028E4A526E70E459E")
}

rule Suspect
{
	strings: 
		$ = "tppy.ynrlzy.cn"
	
	condition:
		1 of them
}
