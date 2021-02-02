/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Spy Twittre
    Rule id: 1926
    Created at: 2016-10-20 07:12:40
    Updated at: 2016-10-20 07:16:26
    
    Rating: #0
    Total detections: 2
*/

import "androguard"

rule Twittre
{
    condition:
        androguard.certificate.sha1("CEEF7C87AA109CB678FBAE9CB22509BD7663CB6E") and not
		androguard.certificate.sha1("40F3166BB567D3144BCA7DA466BB948B782270EA") //original
        
        
}
