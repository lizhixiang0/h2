/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: Shuanet
    Rule id: 1011
    Created at: 2015-11-12 08:49:49
    Updated at: 2015-11-12 08:52:54
    
    Rating: #1
    Total detections: 15
*/

import "androguard"

rule Shuanet : official
{
	meta:
		description = "This rule detects Shuanet aggresive Adware (https://blog.lookout.com/blog/2015/11/04/trojanized-adware/)"
		sample = "-"

	strings:
		$a = {4C 4F 43 41 4C 5F 44 4F 57 4E 5F 43 4F 4E 46 49 47}
		$b = {4E 6F 74 69 66 79 43 65 6E 74 65 72 41 49 44 4C}
		$c = {6F 6E 52 6F 6F 74 57 6F 72 6B}
		$d = {73 68 75 61 6E 65 74}



	condition:

		$a and $b and $c and $d
		
}
