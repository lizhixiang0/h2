/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: MyPleasure_app_1
    Rule id: 4590
    Created at: 2018-06-26 21:18:47
    Updated at: 2018-06-26 21:19:41
    
    Rating: #0
    Total detections: 12489
*/

import "androguard"

rule POB_1
{
	meta:
		description = "Detects few MyPleasure app"
		
	condition:
		(androguard.service(/ch.nth.android.contentabo.service.DownloadAppService/))
		
}
