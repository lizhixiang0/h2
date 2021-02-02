/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: VkSteal
    Rule id: 938
    Created at: 2015-10-16 17:27:10
    Updated at: 2015-10-16 17:32:20
    
    Rating: #0
    Total detections: 24
*/

import "androguard"

rule VKSteal : official
{
	meta:
		description = "This rule detects vK login stealer"
		info = "https://securelist.com/blog/incidents/72458/stealing-to-the-sound-of-music/"

	strings:
		$a = {2F 61 70 2F 3F 6C 3D 25 73 26 70 3D 25 73}
		$b = {2F 73 70 6F 6E 73 6F 72 5F 67 72 6F 75 70 73 2E 74 78 74}
		$c = {63 61 70 74 63 68 61 5F 69 6D 67 3D}
		$d = {70 68 6F 74 6F 5F 31 30 30}
		$e = {75 73 65 72 5F 64 6F 77 6E 6C 6F 61 64 65 64 5F 63 6F 75 6E}


	condition:

		$a and $b and $c and $d and $e
}
