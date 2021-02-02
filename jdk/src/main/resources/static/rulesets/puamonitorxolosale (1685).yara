/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: PUA.Monitor:Xolosale
    Rule id: 1685
    Created at: 2016-07-28 07:53:57
    Updated at: 2017-05-10 11:10:39
    
    Rating: #0
    Total detections: 54
*/

import "androguard"

rule xolosale
{
	strings:
		$ = "919211722715"
		$ = "servernumber"
		$ = "xolo"
		
	condition:
		( androguard.url(/pu6b.vrewap.com:1337/i) or
		androguard.url(/pu6a.vrewap.com:1337/i) ) 
		or 
		all of them
	
}
