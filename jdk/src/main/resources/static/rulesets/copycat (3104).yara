/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: CopyCat
    Rule id: 3104
    Created at: 2017-07-10 11:52:13
    Updated at: 2018-06-25 11:52:21
    
    Rating: #0
    Total detections: 214
*/

import "androguard"

rule clicksummer
{
	meta:
		description = "domains used for copycat malware (CheckPoint)"

	strings:
		$ = ".clickmsummer.com"
		$ = ".mostatus.net"
		$ = ".mobisummer.com"
		$ = ".clickmsummer.com"
		$ = ".hummercenter.com"
		$ = ".tracksummer.com"

	condition:
 		1 of them
		
}
