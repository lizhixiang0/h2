/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Dvmap
    Rule id: 2955
    Created at: 2017-06-09 09:56:09
    Updated at: 2017-06-12 06:43:31
    
    Rating: #0
    Total detections: 40
*/

import "androguard"


rule Dvmap
{
	//https://securelist.com/78648/dvmap-the-first-android-malware-with-code-injection/ 
	
	strings:
		$a = "com.colourblock.flood"

	condition:
		$a and not androguard.certificate.sha1("D75A495C4D7897534CC9910A034820ABD87D7F2F") 
		
}
