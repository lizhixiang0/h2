/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Skunk
    Rule id: 2671
    Created at: 2017-05-10 09:02:44
    Updated at: 2017-05-10 09:05:41
    
    Rating: #0
    Total detections: 12
*/

import "androguard"

rule SMS_Skunk
{
	condition:
		androguard.package_name(/org.skunk/) and
		androguard.permission(/SEND_SMS/)
		
}
