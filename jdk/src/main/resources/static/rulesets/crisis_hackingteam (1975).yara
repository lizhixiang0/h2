/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: x4x1m
    Rule name: Crisis_Hackingteam
    Rule id: 1975
    Created at: 2016-11-23 02:20:01
    Updated at: 2016-11-23 10:29:23
    
    Rating: #0
    Total detections: 418
*/

import "androguard"

rule crisis
{
	meta:
		description = "Crisis pack / Hacking team"
		sample = "29b1d89c630d5d44dc3c7842b9da7e29e3e91a644bce593bd6b83bdc9dbd3037"

	strings:
        $a = "background_Tr6871623"

	condition:
		$a and 
		androguard.permission(/android.permission.SEND_SMS/) and 
		androguard.permission(/android.permission.PROCESS_OUTGOING_CALLS/) and
		androguard.permission(/android.permission.RECORD_AUDIO/)
		
}
