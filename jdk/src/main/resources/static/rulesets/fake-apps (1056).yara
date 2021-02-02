/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Fake Apps
    Rule id: 1056
    Created at: 2015-12-10 12:23:15
    Updated at: 2016-01-13 07:38:21
    
    Rating: #0
    Total detections: 800
*/

import "androguard"

rule HillClimbRacing
{
	meta:
		description = "This rule detects fake application of Hill Climb Racing"
		sample = "e0f78acfc9fef52b2fc11a2942290403ceca3b505a8e515defda8fbf68ac3b13"


	condition:
		androguard.package_name("com.fingersoft.hillclimb") and
		not androguard.certificate.sha1("9AA52CC5C1EA649B45F295611417B4B6DA6324EA")
}
