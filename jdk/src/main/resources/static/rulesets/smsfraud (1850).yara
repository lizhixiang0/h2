/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSFraud
    Rule id: 1850
    Created at: 2016-09-28 12:45:49
    Updated at: 2016-09-28 12:53:01
    
    Rating: #0
    Total detections: 87
*/

import "androguard"

rule simplerule
{
	meta:
		description = "This rule detects a SMS Fraud malware"
		sample = "4ff3169cd0dc6948143bd41cf3435f95990d74538913d8efd784816f92957b85"

	condition:
		androguard.package_name("com.hsgame.hmjsyxzz") or 
		androguard.certificate.sha1("4ECEF2C529A2473C19211F562D7246CABD7DD21A")
		
}
