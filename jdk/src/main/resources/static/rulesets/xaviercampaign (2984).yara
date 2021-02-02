/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: XavierCampaign
    Rule id: 2984
    Created at: 2017-06-13 22:47:35
    Updated at: 2017-06-16 21:47:38
    
    Rating: #0
    Total detections: 25
*/

import "androguard"
import "file"
import "cuckoo"


rule XavierCampaign
{
	meta:
		description = "This rule detects samples from the Xavier campaign"
		sample = "8a72124709dd0cd555f01effcbb42078"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/analyzing-xavier-information-stealing-ad-library-android/"
		
	condition:
		androguard.service(/xavier.lib.message/) and 
		androguard.receiver(/xavier.lib.Xavier/)
	
}
