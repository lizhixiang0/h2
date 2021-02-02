/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: ChinesePorn_2
    Rule id: 3304
    Created at: 2017-08-03 10:03:26
    Updated at: 2017-08-03 10:05:31
    
    Rating: #0
    Total detections: 411
*/

import "androguard"
import "file"
import "cuckoo"


rule ChinesePorn_2
{
	meta:
		description = "This rule detects dirtygirl samples"
		sample = "aeed925b03d24b85700336d4882aeacc"
		
	condition:
		androguard.receiver(/com\.sdky\.lyr\.zniu\.HuntReceive/) and
		androguard.service(/com\.sdky\.jzp\.srvi\.DrdSrvi/)

}
