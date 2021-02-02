/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Fake market
    Rule id: 548
    Created at: 2015-06-03 08:52:05
    Updated at: 2015-08-06 15:20:12
    
    Rating: #0
    Total detections: 56
*/

import "androguard"

rule fake_market
{

	condition:
		androguard.package_name("com.minitorrent.kimill") 
}
