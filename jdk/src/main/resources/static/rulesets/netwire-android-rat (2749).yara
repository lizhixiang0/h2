/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: malhunter
    Rule name: NetWire Android RAT
    Rule id: 2749
    Created at: 2017-05-24 10:06:40
    Updated at: 2017-05-24 10:16:31
    
    Rating: #-1
    Total detections: 416
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "This rule detects the NetWire Android RAT, used to show all Yara rules potential"
		sample = "41c4c293dd5a26dc65b2d289b64f9cb8019358d296b413c192ba8f1fae22533e "

	strings:
		$a = {41 68 4D 79 74 68}

	condition:
		androguard.package_name("ahmyth.mine.king.ahmyth") and
		not file.md5("c99ccf4d61cefa985d94009ad34f697f") and 
		$a 
}
