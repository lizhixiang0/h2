/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: banker_Dew18_2
    Rule id: 5136
    Created at: 2018-12-12 21:33:36
    Updated at: 2018-12-12 21:34:04
    
    Rating: #0
    Total detections: 16
*/

import "androguard"

rule banker_Dew18_2
{
	meta:
		description = "Detects DewExample related samples"
		md5 = "510ed33e1e6488ae21a31827faad74e6"
		
		
	strings:
		$a_2 = "com.ktcs.whowho"
		$a_3 = "KEY_OUTGOING_REPLACE_NUMBER"

	
	condition:
		all of ($a_*)
 			    
				
}
