/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: Copy9
    Rule id: 1473
    Created at: 2016-06-06 03:33:38
    Updated at: 2018-07-25 10:08:32
    
    Rating: #0
    Total detections: 219
*/

import "androguard"

rule Android_Copy9
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "This rule try to detect commercial spyware from Copy9"
		source = "http://copy9.com/"

	condition:
		androguard.service(/com.ispyoo/i) and
        androguard.receiver(/com.ispyoo/i)
}
