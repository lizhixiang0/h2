/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: package
    Rule id: 561
    Created at: 2015-06-05 07:38:49
    Updated at: 2015-08-06 15:20:13
    
    Rating: #0
    Total detections: 233
*/

import "androguard"

rule test: adware
{
		
    condition:
		androguard.app_name(/{d0 a3 d1 81 d1 82 d0 b0 d0 bd d0 be d0 b2 d0 ba d0 b0}/) or androguard.package_name(/com\.tujtr\.rtbrr/)
}
