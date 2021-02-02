/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dgarcia
    Rule name: GeoHotS4
    Rule id: 646
    Created at: 2015-06-30 10:54:27
    Updated at: 2015-08-06 15:20:38
    
    Rating: #0
    Total detections: 2
*/

rule geohotS4
{
	meta:
		description = "Geohot S4"
		
	strings:
		$a = {7C 44 79 44 20 1C FF F7 B0 EE 20 4B 06 1C 01}

	condition:
		$a
		
}
