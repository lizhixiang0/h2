/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Banker
    Rule id: 2278
    Created at: 2017-03-02 12:26:29
    Updated at: 2017-03-03 12:07:41
    
    Rating: #0
    Total detections: 84
*/

import "androguard"


rule Banker
{
	condition:
		androguard.certificate.issuer(/@attentiontrust\.[a-z]{2,3}/) and
		androguard.certificate.issuer(/Attention Trust/)
		
}
