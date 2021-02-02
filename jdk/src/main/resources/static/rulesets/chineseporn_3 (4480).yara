/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Chineseporn_3
    Rule id: 4480
    Created at: 2018-05-29 21:45:20
    Updated at: 2018-05-29 21:55:44
    
    Rating: #0
    Total detections: 45295
*/

import "androguard"

rule Chineseporn_3
{
	meta:
		description = "Detects few Chinese Porn apps"
		
	condition:
		(androguard.receiver(/lx\.Asver/) and
		 androguard.receiver(/lx\.Csver/))
		
}
