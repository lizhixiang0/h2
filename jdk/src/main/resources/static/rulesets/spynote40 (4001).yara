/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: invoker
    Rule name: spynote4.0
    Rule id: 4001
    Created at: 2018-01-18 01:27:37
    Updated at: 2018-02-02 03:29:49
    
    Rating: #0
    Total detections: 34
*/

import "androguard"

rule spynote4
{
	meta:
		description = "Yara rule for detection of  Spynote4.0"
		author = "invoker"

	strings:
		$str_1 = "scream" 
		
	condition:
		androguard.package_name("system.operating.dominance.proj") and 
		all of ($str_*)
}
