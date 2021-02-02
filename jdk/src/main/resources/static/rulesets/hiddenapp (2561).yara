/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: HiddenApp
    Rule id: 2561
    Created at: 2017-04-25 11:48:55
    Updated at: 2017-05-26 10:02:49
    
    Rating: #0
    Total detections: 2186
*/

import "androguard"

rule HiddenApp {
	
	strings:
	  	$ = /ssd3000.top/
		$ = "com.app.htmljavajets.ABKYkDEkBd"

	condition:
		1 of them

}
