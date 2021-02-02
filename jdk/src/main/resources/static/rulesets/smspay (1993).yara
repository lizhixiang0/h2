/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSPay
    Rule id: 1993
    Created at: 2016-11-29 08:43:09
    Updated at: 2016-11-29 08:44:07
    
    Rating: #0
    Total detections: 2465
*/

import "androguard"


rule SMSPay : chinese_porn
{
	meta:
		description = "This rule detects the SMSPay apps"
		sample = "e0fcfe3cc43e613ec733c30511492918029c6c76afe8e9dfb3b644077c77611a"

	condition:
		androguard.certificate.sha1("42867A29DCD05B048DBB5C582F39F8612A2E21CD")
}
