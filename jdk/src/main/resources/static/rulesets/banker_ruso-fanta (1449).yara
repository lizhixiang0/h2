/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Banker_ruso fanta
    Rule id: 1449
    Created at: 2016-05-31 12:55:27
    Updated at: 2016-05-31 12:56:33
    
    Rating: #0
    Total detections: 252
*/

import "androguard"
import "file"
import "cuckoo"


rule fanta
{
	meta:
		description = "This rule detects the koodous application, used to show all Yara rules potential"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
		$a = "commandObServer"
		$b = "ussd(): "
		$c = "const_id_send_sms"
		$d = "const_task_id_send_sms"

	condition:
		all of them
}
