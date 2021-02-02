/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Banker.RuMMS
    Rule id: 1961
    Created at: 2016-11-14 10:28:12
    Updated at: 2016-11-14 10:28:32
    
    Rating: #0
    Total detections: 253
*/

rule RuMMS {
	strings:
		$ = "5.45.78.20"
	condition:
		all of them
}
