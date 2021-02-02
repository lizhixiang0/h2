/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: JinBoShiPin
    Rule id: 1671
    Created at: 2016-07-24 06:31:24
    Updated at: 2016-07-24 08:12:15
    
    Rating: #0
    Total detections: 35816
*/

import "androguard"


rule JinBoShiPin : chinese_porn
{

	condition:
		androguard.app_name("\xe7\xa6\x81\xe6\x92\xad\xe8\xa7\x86\xe9\xa2\x91") // jin bo shi pin 277b8320ceb8481a46198f7b9491aef5e9cf54ecda32ca419d0f1aaa422f34cd
		
}
