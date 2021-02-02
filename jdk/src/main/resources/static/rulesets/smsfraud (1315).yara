/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSFraud
    Rule id: 1315
    Created at: 2016-03-28 09:38:06
    Updated at: 2016-03-28 09:49:22
    
    Rating: #0
    Total detections: 12085
*/

rule nang
{
	meta:
		description = "Little and simple SMSFraud"
		sample = "8f1ee5c8e529ed721c9a8e0d5546be48c2bbc0c8c50a84fbd1b7a96831892551"

	strings:
		$a = "NANG"
		$b = "deliveredPI"
		$c = "totalsms.txt"

	condition:
		all of them
		
}
