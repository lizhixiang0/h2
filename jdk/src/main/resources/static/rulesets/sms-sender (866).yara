/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: SMS SENDER
    Rule id: 866
    Created at: 2015-09-27 15:01:36
    Updated at: 2015-09-27 15:06:22
    
    Rating: #0
    Total detections: 2849
*/

import "androguard"

rule boibaSender
{
	meta:
		description = "Collects info and sends SMS to contacts. Usually faking Candy Crush"

	strings:
		$a = "http://vinaaz.net/check/game.txt"
		$b = "http://192.168.1.12:8080/BoiBaiServer/services/BoiBaiTayRemoteImpl"
		$c = "http://sms_service/boibaitay/"
	condition:
		$a or $b or $c
		
}
