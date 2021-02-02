/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: RuClicker
    Rule id: 3349
    Created at: 2017-08-09 08:43:24
    Updated at: 2017-08-09 08:44:17
    
    Rating: #0
    Total detections: 170
*/

import "androguard"
import "file"
import "cuckoo"


rule RuClicker
{
	strings:
		$ = "CiLscoffBa"
		$ = "FhLpinkJs"
		$ = "ZhGsharecropperFx"

	condition:
 		all of them
}
