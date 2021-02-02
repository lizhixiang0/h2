/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kevinmiston
    Rule name: cafebazaar
    Rule id: 4585
    Created at: 2018-06-25 08:38:48
    Updated at: 2018-09-26 23:13:45
    
    Rating: #1
    Total detections: 1162
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the cafebazaar app or link"

	condition:
		androguard.url(/cafebazaar\.ir/)
		
}
