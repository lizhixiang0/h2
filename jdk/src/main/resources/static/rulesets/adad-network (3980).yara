/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kevinmiston
    Rule name: adad-network
    Rule id: 3980
    Created at: 2018-01-10 16:03:18
    Updated at: 2018-09-26 23:14:24
    
    Rating: #0
    Total detections: 1657
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "adad - network"
	condition:
		androguard.activity(/ir.adad/i) or
		androguard.url(/s\.adad\.ir/)
		
}
