/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: nikchris
    Rule name: Coudw
    Rule id: 709
    Created at: 2015-07-16 08:46:02
    Updated at: 2015-08-06 15:20:54
    
    Rating: #4
    Total detections: 37
*/

import "androguard"

rule Coudw : official
{
	meta:
		description = "This rule detects one Coudw variant"
		// Url: http://www.techknow.me/forum/index.php?topic=8996.0
		// 		http://www.techknow.me/forum/index.php?topic=9121.0
		
		sample = "240F3F5E1E6B4F656DCBF83C5E30BB11677D34FB10135ACC178C0F9E9C592C21"

	strings:
		$a = {2F73797374656D2F62696E2F62757379626F7820696E7374616C6C202D7220}
		$b = {436C6F756473536572766572312E61706B}


	condition:

		$a and $b
		or androguard.url(/s\.cloudsota\.com/)

		
}
