/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: droidcollector
    Rule id: 861
    Created at: 2015-09-26 18:18:08
    Updated at: 2015-09-26 18:52:15
    
    Rating: #0
    Total detections: 3570
*/

import "androguard"


rule droidcollector
{
	meta:
		description = "Detect stealer tool (Sending collected data to ext server"

	strings:
		$a = "http://85.10.199.40/ss/media1.php"
		$b = "http://85.10.199.40/ss/xml22.php"
	condition:
		androguard.url(/85\.10\.199\.40/) or $a or $b
}
