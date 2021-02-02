/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: baal
    Rule name: PostePay sms-fraud
    Rule id: 1434
    Created at: 2016-05-25 16:03:02
    Updated at: 2016-05-25 16:07:15
    
    Rating: #0
    Total detections: 3
*/

import "androguard"


rule postepay_smsFraud
{
	meta:
		description = "Yara detection for PostePay SMS-fraud"

	condition:		
		
		androguard.package_name("me.help.botfix") and
		androguard.certificate.sha1("F3B7734A4BADE62AD30FF4FA403675061B8553FF") and
		androguard.receiver(/\.SmsListener/) and 
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.READ_SMS/) 
		
}
