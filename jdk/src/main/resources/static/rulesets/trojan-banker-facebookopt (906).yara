/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: Trojan Banker FacebookOPT
    Rule id: 906
    Created at: 2015-10-09 14:11:18
    Updated at: 2015-10-09 14:14:41
    
    Rating: #0
    Total detections: 19
*/

import "androguard"

rule facebookopt : banker
{
	meta:
		description = "Android Spy Banker"
		sample = "562da283fab7881ea4fa8ce5d764720d8d87e167cc9bb797a48e7a53a5314fae"

	condition:
		androguard.permission(/android.permission.SEND_SMS/)
		and androguard.permission(/android.permission.CALL_PHONE/)
		and androguard.certificate.sha1("BF0DE1B54673F2092FDC5A75DA4FFC26F65E1602")
}
