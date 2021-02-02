/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: Fake Facebook Apps
    Rule id: 805
    Created at: 2015-08-29 18:07:19
    Updated at: 2015-11-05 09:51:57
    
    Rating: #0
    Total detections: 4732
*/

import "androguard"

rule FakeFacebook
{
	meta:
		description = "Fake Facebook applications"

	condition:
		androguard.app_name("Facebook") and
		not androguard.certificate.sha1("8A3C4B262D721ACD49A4BF97D5213199C86FA2B9")	
}
