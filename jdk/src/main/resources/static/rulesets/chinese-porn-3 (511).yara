/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Chinese porn 3
    Rule id: 511
    Created at: 2015-05-25 05:42:04
    Updated at: 2015-08-06 15:20:08
    
    Rating: #0
    Total detections: 106965
*/

import "androguard"
rule chinese_porn : SMSSend
{

	condition:
		androguard.package_name("com.tzi.shy") or
		androguard.package_name("com.shenqi.video.nfkw.neim") or
		androguard.package_name("com.tos.plabe")
}
