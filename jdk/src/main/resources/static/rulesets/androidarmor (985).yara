/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lifree
    Rule name: AndroidArmor
    Rule id: 985
    Created at: 2015-11-03 12:51:47
    Updated at: 2015-11-03 12:52:30
    
    Rating: #0
    Total detections: 2279
*/

import "androguard"
import "file"
import "cuckoo"


rule packers
{
	meta:
		description = "androidarmor"
		thread_level = 3
		in_the_wild = true

	strings:
		$strings_b = "cc.notify-and-report.net"
		$strings_c = "FK_G+IL7~t-6"


	condition:
		$strings_b or $strings_c
}
