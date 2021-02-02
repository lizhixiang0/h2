/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: DroidboxExample
    Rule id: 1548
    Created at: 2016-06-29 12:36:28
    Updated at: 2016-07-11 13:00:57
    
    Rating: #0
    Total detections: 1737
*/

import "droidbox"

rule example_droidbox
{
	meta:
		description = "This is aexample for Droidbox Ruleset, these numbers are presents in malware"

	condition:
		droidbox.sendsms("18258877494") or droidbox.sendsms("12114")
		
}
