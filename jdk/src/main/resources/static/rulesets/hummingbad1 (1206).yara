/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: oguzhantopgul
    Rule name: HummingBad1
    Rule id: 1206
    Created at: 2016-02-15 06:56:40
    Updated at: 2016-02-15 07:10:23
    
    Rating: #0
    Total detections: 69
*/

import "androguard"
import "file"

rule HummingBad : urls
{
	meta:
		description = "This rule detects APKs in HummingBad Malware Chain"
		sample = "f2b98fd772e6ac1481f6c7bb83da9fdffc37d02b2f95e39567047d948a793e6d "

	strings:
		$string_1 = "assets/ResolverActivity.apk"
		$string_2 = "assets/readl"
		
		$string_3 = "assets/sailer.data"
		
		$string_4 = "assets/a.bmp"
		$string_5 = "assets/support.bmp"
		$string_6 = "assets/pc"
		$string_7 = "assets/daemon"
		
		$string_8 = "assets/ep"
		$string_9 = "assets/fx"
		
	condition:
		($string_1 and $string_3 and $string_2) or 
		($string_3 and $string_4 and $string_5 and $string_6 and $string_7) or 
		($string_6 and $string_7 and $string_8 and $string_9) or
		($string_6 and $string_7)
		
}
