/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: agprados
    Rule name: SandroRat Ruleset
    Rule id: 1274
    Created at: 2016-03-14 13:15:44
    Updated at: 2016-03-14 13:19:54
    
    Rating: #0
    Total detections: 10805
*/

rule sandrorat
{
	meta:
		description = "This rule detects Sandrorat samples"

	strings:
		$a = "SandroRat"

	condition:
		$a		
}
