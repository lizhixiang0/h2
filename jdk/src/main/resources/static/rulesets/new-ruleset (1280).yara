/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Dcarrion
    Rule name: New Ruleset
    Rule id: 1280
    Created at: 2016-03-14 13:15:53
    Updated at: 2016-03-14 13:19:16
    
    Rating: #0
    Total detections: 11241
*/

rule sandrorat
{
	meta:
		description = "This rule detects SandroRat samples"
		
	strings:
		$a = "SandroRat"
	condition:
		$a
		
}
