/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Chinese porn 4
    Rule id: 538
    Created at: 2015-06-01 10:31:05
    Updated at: 2015-08-06 15:20:11
    
    Rating: #0
    Total detections: 421236
*/

import "androguard"
rule chineseporn4 : SMSSend
{

	condition:
		androguard.activity(/com\.shenqi\.video\.Welcome/) or
		androguard.package_name("org.mygson.videoa.zw")
}
