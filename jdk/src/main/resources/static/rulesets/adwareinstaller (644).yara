/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Adware:installer
    Rule id: 644
    Created at: 2015-06-29 13:16:28
    Updated at: 2015-08-06 15:20:38
    
    Rating: #0
    Total detections: 9
*/

import "androguard"

rule adware: installer
{

	condition:
		androguard.package_name("installer.com.bithack.apparatus")
		
		
}
