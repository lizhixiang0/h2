/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fishman
    Rule name: New Ruleset
    Rule id: 4197
    Created at: 2018-02-09 11:26:30
    Updated at: 2018-02-09 11:37:04
    
    Rating: #0
    Total detections: 1245
*/

import "androguard"



rule taskhijack3 : official
{
	meta:
		date = "2018-02-09"
		description = "Task Hijack #HST3 spoofing"
		reference = "https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf"
		reference1 = "Power by dmanzanero"
		
	strings:
		$a = /taskAffinity\s*=/
		$b = /allowTaskReparenting\s*=/
		$file = "AndroidManifest.xml"
		
	condition:
		$file and ($a or $b)
		
}
