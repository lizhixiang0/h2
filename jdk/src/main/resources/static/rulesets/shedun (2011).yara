/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: x4x1m
    Rule name: Shedun
    Rule id: 2011
    Created at: 2016-12-04 12:19:32
    Updated at: 2016-12-04 13:12:17
    
    Rating: #0
    Total detections: 499423
*/

rule shedun
{
	meta:
		description = "Detects libcrypt_sign used by shedun"
		sample = "919f1096bb591c84b4aaf964f0374765c3fccda355c2686751219926f2d50fab"

	strings:
		$a = "madana!!!!!!!!!"
		$b = "ooooop!!!!!!!!!!!"
		$c = "hehe you never know what happened!!!!"

	condition:
		all of them
		
}
