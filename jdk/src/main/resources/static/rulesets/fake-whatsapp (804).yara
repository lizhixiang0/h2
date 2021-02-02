/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: Fake WhatsApp
    Rule id: 804
    Created at: 2015-08-29 18:00:37
    Updated at: 2015-08-29 18:08:29
    
    Rating: #1
    Total detections: 5114
*/

import "androguard"

rule FakeWhatsApp
{
	meta:
		description = "Fake WhatsApp applications"
		
	condition:
		androguard.app_name("WhatsApp") and
		not androguard.certificate.sha1("38A0F7D505FE18FEC64FBF343ECAAAF310DBD799")
}
