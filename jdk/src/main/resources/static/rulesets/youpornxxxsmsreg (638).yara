/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: youpornxxx.SMSReg
    Rule id: 638
    Created at: 2015-06-26 13:01:47
    Updated at: 2016-02-13 12:59:40
    
    Rating: #0
    Total detections: 275
*/

import "androguard"

private rule activity
{

	condition:
		androguard.url(/hotappsxx\.com/) or
		androguard.url(/xvideozlive\.xxx/)
		
}

rule youpornxxx
{
	meta:
		description = "SMSReg variant related with Youpornxxx"
		sample = "686a424988ab4a9340c070c8ac255b632c617eac83680b4babc6f9c3d942ac36"

	strings:
		$a = "newapps/youpornxxx" wide ascii

	condition:
		$a or activity
		
}
