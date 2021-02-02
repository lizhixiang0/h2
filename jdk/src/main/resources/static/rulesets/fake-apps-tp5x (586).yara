/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: Fake apps - tp5x
    Rule id: 586
    Created at: 2015-06-15 15:22:39
    Updated at: 2015-08-06 15:20:16
    
    Rating: #0
    Total detections: 4449
*/

rule fake_apps
{
	meta:
		description = "Fake Apps"

	strings:
		$a = "150613072127Z"
		$b = "421029072127Z0I1"

	condition:
		$a or $b
}
