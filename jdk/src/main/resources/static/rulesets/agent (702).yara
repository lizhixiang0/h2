/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: Agent
    Rule id: 702
    Created at: 2015-07-15 12:25:57
    Updated at: 2015-08-06 16:00:38
    
    Rating: #3
    Total detections: 10168
*/

import "androguard"

rule Agent : official
{
	meta:
		description = "This rule detects one Agent variant w/ Admin Access"
		sample = "52f0a9d60f9e6ead70fd152aa4a3a8865215dd685128581697ce3ae3db768105"

	strings:
		$a = {6E 2E 41 44 44 5F 44 45 56 49 43 45 5F 41 44 4D 49 4E}
		$b = {6F 6D 2E 61 6E 72 64 2E 73 79 73 73 65 72 76 69 63 65 73 2F 66 69 6C 65 73 2F 73 75}


	condition:

		$a and $b

		
}
