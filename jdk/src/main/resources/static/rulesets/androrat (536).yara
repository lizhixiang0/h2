/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: AndroRAT
    Rule id: 536
    Created at: 2015-05-31 02:41:06
    Updated at: 2016-02-13 13:03:28
    
    Rating: #0
    Total detections: 10311
*/

rule AndroRAT

{
	meta:
		description = "AndroRAT"

	strings:
		$a = "Lmy/app/client/ProcessCommand" wide ascii
		$b = "AndroratActivity" wide ascii
		$c = "smsKeyWord" wide ascii
		$d = "numSMS" wide ascii

	condition:
		$a and ($b or $c or $d)
}
