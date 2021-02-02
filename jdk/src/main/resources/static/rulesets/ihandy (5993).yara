/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: deletescape
    Rule name: iHandy
    Rule id: 5993
    Created at: 2019-10-24 12:57:36
    Updated at: 2019-10-24 12:58:30
    
    Rating: #0
    Total detections: 1
*/

import "cuckoo"


rule iHandy
{
	meta:
		description = "Detects apps created by/conntected to iHandy"

	condition:
		cuckoo.network.dns_lookup(/appcloudbox.net/)
		
}
