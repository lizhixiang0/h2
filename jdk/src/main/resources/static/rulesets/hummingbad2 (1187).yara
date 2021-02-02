/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: oguzhantopgul
    Rule name: HummingBad2
    Rule id: 1187
    Created at: 2016-02-08 13:34:00
    Updated at: 2016-02-11 12:30:46
    
    Rating: #0
    Total detections: 864
*/

import "androguard"
import "file"

rule HummingBad : urls
{
	meta:
		description = "This rule detects APKs in HummingBad Malware Chain"
		sample = "72901c0214deb86527c178dcd4ecf73d74cac14eaaaffc49eeb00c7fb3343e79"

	strings:
		$string_1 = "assets/daemon.bmp"
		$string_2 = "assets/module_encrypt.jar"
		$string_3 = "assets/daemon"

	condition:
		($string_1 or $string_3) and $string_2
		
}
