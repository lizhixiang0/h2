/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: dgarcia
    Rule name: suidext
    Rule id: 667
    Created at: 2015-07-07 12:31:44
    Updated at: 2017-04-21 14:01:03
    
    Rating: #0
    Total detections: 155
*/

import "androguard"
import "file"
import "cuckoo"


rule suidext : official
{
	meta:
		description = "detect suid"

	strings:
		$a = {50 40 2d 40 55 53 5e 2d}

	condition:
		$a
		
}
