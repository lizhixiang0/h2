/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: RansomWare
    Rule id: 1982
    Created at: 2016-11-25 10:59:14
    Updated at: 2016-11-28 11:09:10
    
    Rating: #2
    Total detections: 127
*/

import "androguard"

rule fbilocker {
	strings:	
		$a1 = "comdcompdebug.500mb.net/api33"
		$a2 = "itsecurityteamsinc.su"
		$a3 = "api.php"
    condition:
        androguard.certificate.sha1("A4DF11815AF385578CEC757700A3D1A0AF2136A8") or
		2 of ($a*)
}
