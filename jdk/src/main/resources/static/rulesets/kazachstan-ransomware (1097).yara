/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: boni11
    Rule name: Kazachstan Ransomware
    Rule id: 1097
    Created at: 2016-01-04 10:43:33
    Updated at: 2016-01-04 13:05:52
    
    Rating: #5
    Total detections: 133
*/

rule ransomware
{
	meta:
		description = "This rule detects Ransomware"
		sample = "185c5b74d215b56ba61b4cebd748aec86e478c6ac06aba96d98eff58b24ee824"
		source = "https://twitter.com/LukasStefanko/status/683997678821322752"

	strings:
		$a = "findFrontFacingCamera"
		$c = "runReceiver"
		$d = "onCarete"
		
	condition:
		all of them
		
}
