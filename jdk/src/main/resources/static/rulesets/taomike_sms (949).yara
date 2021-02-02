/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Taomike_sms
    Rule id: 949
    Created at: 2015-10-27 06:30:47
    Updated at: 2015-10-27 07:05:21
    
    Rating: #0
    Total detections: 7770
*/

import "androguard"



rule koodous : official
{
	meta:
		description = "http://researchcenter.paloaltonetworks.com/2015/10/chinese-taomike-monetization-library-steals-sms-messages/"

	condition:
		androguard.url("http://112.126.69.51/2c.php")
		
}
