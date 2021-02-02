/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: oguzhantopgul
    Rule name: Mapin Dropper
    Rule id: 888
    Created at: 2015-10-05 13:58:32
    Updated at: 2016-01-06 11:46:56
    
    Rating: #1
    Total detections: 53
*/

import "androguard"
import "file"
import "cuckoo"


rule MapinDropper
{
	meta:
		description = "This rule detects mapin dropper files"
		sample = "745e9a47febb444c42fb0561c3cea794"

	strings:
		$a = "assets/systemdataPK"
		$b = "assets/systemdata"
		$e = "assets/resourcea"
		$f = "assets/resourceaPK"

	condition:
		$a or $b or $e or $f
}
