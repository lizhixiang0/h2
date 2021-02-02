/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: WhatsAppGold_Test
    Rule id: 1426
    Created at: 2016-05-25 03:35:39
    Updated at: 2016-05-25 16:53:56
    
    Rating: #1
    Total detections: 33
*/

import "androguard"
import "file"
import "cuckoo"


rule WhatsAppGold
{
	meta:
		description = "Rule to detect WhatsApp Gold"
		sample = "26fe32f823c9981cb04b9898a781c5cdf7979d79b7fdccfb81a107a9dd1ef081"
			
	strings:
		$a = "mahmoodab99@gm"
			
	condition:
		all of ($a)
}
