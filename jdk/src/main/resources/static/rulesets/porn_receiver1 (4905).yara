/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Porn_receiver1
    Rule id: 4905
    Created at: 2018-09-26 19:03:17
    Updated at: 2018-09-26 19:05:51
    
    Rating: #0
    Total detections: 1735
*/

import "androguard"

rule Porn_receiver1
{
	meta:
		description = "Catches Porn apps - 0679099c90621db26d92bbb2467542a1"
		
	condition:
		(
		 androguard.receiver(/ts\.xd\.com\.Dw/) and
		 androguard.receiver(/com\.zxhy\.zf\.r\.D/) and
		 androguard.activity(/com\.test\.zepasub\.JActivity/) and
		 androguard.activity(/com\.test\.hown\.NActivity/) and
		 androguard.activity(/ys\.cs\.com\.Xs/)
		 )
		
}
