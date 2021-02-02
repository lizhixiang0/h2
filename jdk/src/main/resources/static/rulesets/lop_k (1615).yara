/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: RootSniff
    Rule name: lop_K
    Rule id: 1615
    Created at: 2016-07-13 08:17:55
    Updated at: 2016-07-13 08:24:01
    
    Rating: #0
    Total detections: 115
*/

import "androguard"

rule lop_K
{
	meta:
		description = "This rule detects the lop files"
		sample = "f8537cc4bc06be5dd47cdee422c3128645d01a2536f6fd54d2d8243714b41bdd"

	strings:
		$a = "assets/daemon"
		$b = "assets/exp"

	condition:
		$a and $b
}
