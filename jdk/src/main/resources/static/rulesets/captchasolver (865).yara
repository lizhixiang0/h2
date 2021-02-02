/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: CaptchaSolver
    Rule id: 865
    Created at: 2015-09-27 11:25:27
    Updated at: 2015-09-27 11:27:18
    
    Rating: #2
    Total detections: 8039
*/

import "androguard"



rule koodous : official
{
	meta:
		description = "Refering to background site so captchas get solved"

	strings:
		$a = "http://antigate.com/in.php"
		$b = "http://antigate.com/"
	condition:
		$a or 
		$b
		
}
