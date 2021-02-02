/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Facebook Spy GhostTeam
    Rule id: 4269
    Created at: 2018-03-14 12:48:42
    Updated at: 2018-03-14 12:49:07
    
    Rating: #0
    Total detections: 7
*/

import "androguard"

rule detection
{
    
	strings:
		$ = "mspace.com.vn"
		$ = "optimuscorp.pw"
		$ = "ads_manager/get_facebook_ads_manager.php" 

	
	condition:
		2 of them or
		androguard.url("mspace.com.vn") or
		androguard.url("optimuscorp.pw") or
		androguard.certificate.sha1("A7E0323BFEFED2929F62EFC015ED465409479F6F") or
		androguard.certificate.issuer(/assdf/)
}
