/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: Btest
    Rule id: 813
    Created at: 2015-09-04 08:21:03
    Updated at: 2015-09-04 10:48:03
    
    Rating: #2
    Total detections: 33948
*/

import "androguard"
import "file"
import "cuckoo"


rule Btest
{
	meta:
		description = "btest"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_a = "aschannel" fullword
		$strings_b = "activesend" fullword
		$strings_c = "b_zq_lemon001" fullword


	

	condition:
		$strings_a or $strings_b or $strings_b or $strings_c
}
