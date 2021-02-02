/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: Mobidash
    Rule id: 596
    Created at: 2015-06-17 07:15:04
    Updated at: 2015-08-06 15:20:18
    
    Rating: #0
    Total detections: 6373
*/

//https://koodous.com/#/apks/c77eed5e646b248079507973b2afcf866234001166f6d280870e624932368529
//https://koodous.com/#/apks/bdfbf9de49e71331ffdfd04839b2b0810802f8c8bb9be93b5a7e370958762836
//https://koodous.com/#/apks/fcf88c8268a7ac97bf10c323eb2828e2025feea13cdc6554770e7591cded462d

import "androguard"


rule mobidash : advertising
{
	meta:
		description = "This rule detects MobiDash advertising"
		sample = "c77eed5e646b248079507973b2afcf866234001166f6d280870e624932368529"

	strings:
		$a = "res/raw/ads_settings.json"
		$b = "IDATx"

	condition:
		($a or $b) and androguard.activity(/mobi.dash.*/)

		
}
