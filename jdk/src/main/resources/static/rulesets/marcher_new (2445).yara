/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: Marcher_new
    Rule id: 2445
    Created at: 2017-04-10 17:49:26
    Updated at: 2017-04-11 16:59:28
    
    Rating: #0
    Total detections: 219
*/

import "androguard"
import "file"
import "cuckoo"


rule Marcher_new
{
	meta:
		description = "This rule detects new Marcher variant with device admin notification screen"
		sample = "b956e12475f9cd749ef3af7f36cab8b20c5c3ae25a13fa0f4927963da9b9256f"

	strings:
		$a = "res/xml/device_admin_new.xml"
		

	condition:
		$a
		
}
