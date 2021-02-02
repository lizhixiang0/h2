/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: Porn (Experimental)
    Rule id: 711
    Created at: 2015-07-16 11:12:25
    Updated at: 2017-06-07 09:49:54
    
    Rating: #0
    Total detections: 16643
*/

import "androguard"

rule Porn : official
{
	meta:
		description = "Experimental rule about Porn samples"
		sample = "-"

	strings:
		$a = "porn" nocase

	condition:
	
		androguard.package_name(/porn/) and $a 
		or (androguard.package_name(/porn/) and $a and androguard.permission(/android.permission.SEND_SMS/))
			
}
