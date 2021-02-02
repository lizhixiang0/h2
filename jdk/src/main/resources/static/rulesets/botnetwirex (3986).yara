/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: BotNet.WireX
    Rule id: 3986
    Created at: 2018-01-11 07:24:50
    Updated at: 2018-04-16 09:21:33
    
    Rating: #0
    Total detections: 9
*/

rule WireX
{
	strings:
		$ = "g.axclick.store"
		$ = "ybosrcqo.us"
		$ = "u.axclick.store"
    	$ = "p.axclick.store"

	condition:
		1 of them
		
}
