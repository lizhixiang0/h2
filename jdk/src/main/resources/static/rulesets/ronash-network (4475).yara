/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kevinmiston
    Rule name: ronash-network
    Rule id: 4475
    Created at: 2018-05-27 18:41:21
    Updated at: 2018-09-26 23:13:36
    
    Rating: #0
    Total detections: 1811
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "ronash - pushe"
	condition:
		androguard.activity(/ronash/i) or
		androguard.url(/ronash\.co/)
		
}
