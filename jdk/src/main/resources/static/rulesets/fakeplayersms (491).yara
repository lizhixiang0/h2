/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: OpenAntivirus
    Rule name: FakePlayerSMS
    Rule id: 491
    Created at: 2015-05-13 15:42:16
    Updated at: 2015-08-06 15:20:05
    
    Rating: #1
    Total detections: 1333
*/

import "androguard"

rule FakePlayerSMS
{
	condition:
		androguard.app_name(/PornoPlayer/) and
		androguard.permission(/SEND_SMS/)		
}
