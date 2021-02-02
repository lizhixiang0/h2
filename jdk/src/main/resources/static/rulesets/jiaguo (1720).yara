/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: RootSniff
    Rule name: Jiaguo
    Rule id: 1720
    Created at: 2016-08-03 12:43:06
    Updated at: 2016-08-04 06:25:56
    
    Rating: #0
    Total detections: 126826
*/

import "androguard"

rule Jiaguo
{
	meta:
		description = "Jiaguo"
		sample = "0a108ace8c317df221d605b2e3f426e4b3712e480f8a780f3c9c61e7bc20c520"

	strings:
		$a = "assets/libjiagu.so"
		$b = "assets/libjiagu_x86.so"

	condition:
		$a and $b
}
