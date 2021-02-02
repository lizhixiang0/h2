/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Trojan.Click
    Rule id: 4267
    Created at: 2018-03-14 11:21:41
    Updated at: 2018-03-14 11:25:50
    
    Rating: #0
    Total detections: 8
*/

import "androguard"

rule Click415to417
{
	strings:
	 $ = "http://apk-archive.ru"
	 $ = "aHR0cDovL2Fway1hcmNoaXZlLnJ1L2dvb2dsZXBsYXlhcHBzL2NoZWNrL281L2luZGV4LnBocD9pbXNpPQ"
	 
	condition:
		androguard.url(/apk-archive.ru/i)
		or 
		1 of them
	
}
