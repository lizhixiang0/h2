/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: NikitaBuchka
    Rule name: Simpo clicker
    Rule id: 1956
    Created at: 2016-11-09 10:34:53
    Updated at: 2016-11-09 10:41:38
    
    Rating: #0
    Total detections: 5
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Turkish Simpo clicker, sometimes gets on the Google Play"
		sample = "https://koodous.com/apks/25d9c7c7d71c15e505fc866b471dbc59a0a3159828355af7179f96c380709d15"

	strings:
		$a = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67} // setComponentEnabledSetting
		$b = {58 2d 52 65 71 75 65 73 74 65 64 2d 57 69 74 68} // X-Requested-With
		$c = {2e 78 79 7a 2f} // ./xyz
	condition:
		filesize < 300KB and
		$a and
		$b and
		$c		
}
