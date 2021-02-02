/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: LeakerLocker
    Rule id: 3183
    Created at: 2017-07-18 07:18:09
    Updated at: 2017-07-19 12:20:39
    
    Rating: #0
    Total detections: 420
*/

import "androguard"
import "file"
import "cuckoo"


rule LeakerLocker
{
	meta:
		description = "This rule detects Leaker Locker samples"
		sample = "8a72124709dd0cd555f01effcbb42078"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/leakerlocker-mobile-ransomware-acts-without-encryption/"
		
	condition:
		androguard.receiver(/receiver.LockScreenReceiver/)
	
}
