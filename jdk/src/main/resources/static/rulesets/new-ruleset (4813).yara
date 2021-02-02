/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: howiepku
    Rule name: New Ruleset
    Rule id: 4813
    Created at: 2018-08-16 03:53:48
    Updated at: 2018-08-16 03:57:47
    
    Rating: #0
    Total detections: 0
*/

rule suoji
{
	meta:
		description = "suoji"

	strings:
		$a = "&#x9501;&#x673A;&#x751F;&#x6210;&#x5668;"
		
	condition:
		$a
		
}
