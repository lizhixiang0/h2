/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSPay
    Rule id: 1737
    Created at: 2016-08-12 10:52:37
    Updated at: 2016-08-15 19:04:28
    
    Rating: #0
    Total detections: 64827
*/

import "androguard"

rule SMSPay
{
	meta:
		description = "This rule detects SMSPay apps"
		sample = "32e322cb0f2e39a6ddc2a9671f262e9f0e3160255710acd6769cb3edf515f36f"

	strings:
		$a = "To activate the application, you must allow the sending of a query using short numbers. For complete information on pricing can be found at the web site: http://www.mobi911.ru/" ascii wide

	condition:
		$a
		
}

rule SMSPay2
{
	meta:
		sample = "4f75890ff99ff8e94b6f7f4b33f9c21d482b2dffb78ced72484acb74e14bb2e7"
	condition:
		androguard.certificate.sha1("6818663E1B038E42D7B8CBCF63CF3D470DA90124")
}
