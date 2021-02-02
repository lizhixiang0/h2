/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kevinmiston
    Rule name: mono-network
    Rule id: 4481
    Created at: 2018-05-29 23:10:59
    Updated at: 2018-09-26 23:13:22
    
    Rating: #0
    Total detections: 167
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "mono - network"
	condition:
		androguard.service(/ir.mono/i) or
		androguard.url(/api.\mono\.ir/)
		
}
