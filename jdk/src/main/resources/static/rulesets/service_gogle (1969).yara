/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: service_gogle
    Rule id: 1969
    Created at: 2016-11-22 08:05:09
    Updated at: 2016-11-22 08:05:33
    
    Rating: #0
    Total detections: 345
*/

import "androguard"

rule Service:Gogle
{
	condition:
		androguard.service("com.module.yqural.gogle")
}
