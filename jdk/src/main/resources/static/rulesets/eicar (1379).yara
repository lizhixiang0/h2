/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: EICAR
    Rule id: 1379
    Created at: 2016-05-09 13:02:21
    Updated at: 2016-05-09 13:07:34
    
    Rating: #0
    Total detections: 191
*/

rule eicar
{
	meta:
		description = "EICAR-AV-Test"
		source = "http://www.eicar.org/86-0-Intended-use.html"

	strings:
		$eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii wide

	condition:
		$eicar
}
