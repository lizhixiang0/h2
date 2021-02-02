/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: hostingmy0@gmail.com
    Rule id: 500
    Created at: 2015-05-15 14:01:48
    Updated at: 2015-08-06 15:20:06
    
    Rating: #0
    Total detections: 12191
*/

import "androguard"

rule hostingmy
{
	condition:
		androguard.certificate.issuer(/hostingmy0@gmail.com/)
}
