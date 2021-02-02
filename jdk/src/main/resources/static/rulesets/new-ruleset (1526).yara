/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: crontab
    Rule name: New Ruleset
    Rule id: 1526
    Created at: 2016-06-22 16:43:16
    Updated at: 2016-10-28 23:19:25
    
    Rating: #0
    Total detections: 21
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{

	condition:
		androguard.certificate.sha1("74D37EED750DBA0D962B809A7A2F682C0FB0D4A5") 
		
}
