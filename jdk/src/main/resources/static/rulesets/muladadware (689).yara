/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: Mulad.Adware
    Rule id: 689
    Created at: 2015-07-14 08:16:24
    Updated at: 2016-02-13 13:01:11
    
    Rating: #0
    Total detections: 40963
*/

import "androguard"

rule Mulad
{
	meta:
        description = "Evidences of Mulad Adware via rixallab component"
	strings:
		$1 = "Lcom/rixallab/ads/" wide ascii

   	condition:
    	$1 or androguard.service(/com\.rixallab\.ads\./)
}
