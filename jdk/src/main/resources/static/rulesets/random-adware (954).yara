/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fsalido
    Rule name: Random Adware
    Rule id: 954
    Created at: 2015-10-29 14:04:05
    Updated at: 2015-11-17 07:05:25
    
    Rating: #0
    Total detections: 0
*/

import "androguard"

$a = "/cellphone-tips\.com/"

rule random: adware
{
    condition:
        androguard.url(/cellphone-tips\.com/) or 
		$a
}
