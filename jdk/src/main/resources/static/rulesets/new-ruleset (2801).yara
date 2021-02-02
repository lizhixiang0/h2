/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: richardeus1
    Rule name: New Ruleset
    Rule id: 2801
    Created at: 2017-05-29 00:28:08
    Updated at: 2017-05-29 00:33:56
    
    Rating: #0
    Total detections: 156
*/

rule sample

{
	meta:
		description = "sample"
	strings:
		$a = "185.62.188.32"
		$b = "TYPE_SMS_CONTENT"
		$c = "getRunningTasks"

	condition:
		$b and ($a or $c)
}
