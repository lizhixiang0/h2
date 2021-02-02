/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: mwhunter
    Rule name: AceCard - Overlay-Trojan
    Rule id: 2443
    Created at: 2017-04-10 06:43:37
    Updated at: 2017-04-26 07:49:22
    
    Rating: #1
    Total detections: 122
*/

import "androguard"

rule AceCard : Overlay Trojan
{
	meta:
		description = "AceCard Trojan / Overlay-Attacks"
		source = "https://securelist.com/blog/research/73777/the-evolution-of-acecard/"

	strings:
		$command_1 = "#intercept_sms_start"
		$command_2 = "#intercept_sms_stop"
		$command_3 = "#listen_sms_start"
		$command_4 = "#listen_sms_stop"
		$command_5 = "#send_sms"
		$command_6 = "#ussd"

	condition:
		2 of ($command_*) and
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.GET_TASKS/) and
		androguard.filter(/.*DEVICE_ADMIN_ENABLED.*/)
}
