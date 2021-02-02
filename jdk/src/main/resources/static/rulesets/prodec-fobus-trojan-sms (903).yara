/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: Prodec - Fobus - Trojan Sms
    Rule id: 903
    Created at: 2015-10-09 11:24:34
    Updated at: 2015-10-09 11:50:46
    
    Rating: #0
    Total detections: 2771
*/

import "androguard"

rule podec_fobus : smstrojan
{
	meta:
		description = "Android.Podec SMS Trojan bypasses CAPTCHA sample"
		url = "http://contagiominidump.blogspot.com.es/2015/03/androidpodec-sms-trojan-bypasses.html"
		sample = "5616840a66ce35ac1f94b5c1737935931dad8a49fc7d35d21128b9a52f65e777"

	condition:
		androguard.permission(/android.permission.SEND_SMS/)
		and androguard.certificate.sha1("671FEA3319B82E5325AB19218188EC35CC2619E5")
		and androguard.url("https://api.rollbar.com/api/1/items/")
}
