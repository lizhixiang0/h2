/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kevinmiston
    Rule name: hamrahpay
    Rule id: 4507
    Created at: 2018-06-07 20:46:03
    Updated at: 2018-09-26 23:14:34
    
    Rating: #0
    Total detections: 378
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "hamrahpay.com"
	condition:
		androguard.url(/hamrahpay\.com/)
		
}
