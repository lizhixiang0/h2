/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: SVPeng
    Rule id: 4313
    Created at: 2018-04-05 11:56:16
    Updated at: 2018-04-05 11:56:20
    
    Rating: #0
    Total detections: 21
*/

import "androguard"


rule svpeng
{
	meta:
		description = "Trojan-Banker.AndroidOS.Svpeng"
		sample = "62aaff01aef5b67637676d79e8ec40294b15d6887d9bce01b11c6ba687419302"

	condition:
		androguard.receiver("com.up.net.PoPoPo") or
		androguard.receiver("com.up.net.PusyCat")
		
}

rule svpeng2
{
	strings:
		$= "http://217.182.174.92/jack.zip"
	condition:
		all of them
}
