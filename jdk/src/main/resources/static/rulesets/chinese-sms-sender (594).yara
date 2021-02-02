/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: Chinese SMS Sender
    Rule id: 594
    Created at: 2015-06-16 19:35:45
    Updated at: 2015-08-06 15:20:18
    
    Rating: #0
    Total detections: 41287
*/

import "androguard"

rule chineseSMSSender
{
	condition:
		androguard.package_name("com.android.phonemanager") and
		androguard.permission(/android.permission.SEND_SMS/)
}
