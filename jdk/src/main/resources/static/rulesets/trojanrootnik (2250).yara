/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Trojan.RootNik
    Rule id: 2250
    Created at: 2017-02-16 10:31:10
    Updated at: 2017-02-16 10:31:26
    
    Rating: #0
    Total detections: 0
*/

rule RootNik {
	meta:
	description = "https://blog.fortinet.com/2017/01/26/deep-analysis-of-android-rootnik-malware-using-advanced-anti-debug-and-anti-hook-part-ii-analysis-of-the-scope-of-java"
		
	strings:

		$ = "grs.gowdsy.com"
		$ = "gt.rogsob.com"
		$ = "gt.yepodjr.com"
		$ = "qj.hoyebs.com"
		$ = "qj.hoyow.com"
	
	condition:
		1 of them
		
}
