/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: sppromo_fakeapps
    Rule id: 5065
    Created at: 2018-11-19 22:52:53
    Updated at: 2018-11-20 19:34:02
    
    Rating: #0
    Total detections: 330
*/

import "androguard"

rule sppromo_fakeapps
{
	meta:
		description = "Detects few shopping related apps which redirect to a malicious website"
		
	strings:
		$a_1 = "mobilpakket/MainActivity"
		$a_2 = "http://sppromo.ru/apps.php?"
		
	
	condition:
		all of ($a_*)
 			    
				
}
