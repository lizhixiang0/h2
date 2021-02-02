/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: Fake Pokemon Go
    Rule id: 1616
    Created at: 2016-07-13 08:21:53
    Updated at: 2016-07-14 13:28:44
    
    Rating: #1
    Total detections: 880
*/

import "androguard"

rule pokemongo : fake
{
	meta:
		description = "This rule detects fakes Pokemon Go apps "
		sample = ""

	condition:
		(androguard.package_name("com.nianticlabs.pokemongo") or androguard.app_name("Pokemon GO")) and not
		androguard.certificate.sha1("321187995BC7CDC2B5FC91B11A96E2BAA8602C62")
		
}
