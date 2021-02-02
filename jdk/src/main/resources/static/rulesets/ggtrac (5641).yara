/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: omeh2003
    Rule name: GGTRAC
    Rule id: 5641
    Created at: 2019-06-23 02:35:29
    Updated at: 2019-06-23 02:40:16
    
    Rating: #0
    Total detections: 61
*/

import "androguard"
import "file"
import "cuckoo"


rule GGTRACK_detecrot : trojan
{
	
	condition:
		androguard.url("http://ggtrack.org/") or
		androguard.url(/ggtrack\.org/) 
		

		
}
