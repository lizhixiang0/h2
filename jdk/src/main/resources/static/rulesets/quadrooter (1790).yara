/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: RootSniff
    Rule name: QuadRooter
    Rule id: 1790
    Created at: 2016-09-02 09:15:06
    Updated at: 2016-09-02 09:16:53
    
    Rating: #0
    Total detections: 416
*/

import "androguard"
import "file"
import "cuckoo"


rule QuadRooter
{
	meta:
		description = "QuadRooter"
		sample = ""

	strings:
		$a = "/dev/kgsl-3d0"

	condition:
		
		$a
}
