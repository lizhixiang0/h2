/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSFraud - Chinese
    Rule id: 792
    Created at: 2015-08-25 11:20:34
    Updated at: 2015-08-25 11:23:57
    
    Rating: #0
    Total detections: 1915
*/

import "androguard"


rule SMSFraud : chinese
{
	meta:
		description = "Simulate apps with chinese name to make sms fraud."
		sample = "64f4357235978f15e4da5fa8514393cf9e81fc33df9faa8ca9b37eef2aaaaaf7"


	condition:
		androguard.certificate.sha1("24C0F2D7A3178A5531C73C0993A467BE1A4AF094")
}
