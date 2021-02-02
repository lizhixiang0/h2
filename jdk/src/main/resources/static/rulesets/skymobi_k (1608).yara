/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: RootSniff
    Rule name: SKYMOBI_K
    Rule id: 1608
    Created at: 2016-07-12 12:37:00
    Updated at: 2016-07-12 13:09:19
    
    Rating: #0
    Total detections: 55630
*/

import "androguard"

rule SKYMOBI
{
	meta:
		description = "Skymobi H"
		sample = "e9562f3ef079bb721d309b77544f83aa5ac0325f03e60dca84c8e041342691f2"

	strings:
		$a = "loadLibrary"
		$b = "assets/libcore.zipPK"
		$c = "assets/libcore2.zipPK"
		$d = "assets/SkyPayInfo.xmlPK"

	condition:
		$a and $b and $c and $d
}
