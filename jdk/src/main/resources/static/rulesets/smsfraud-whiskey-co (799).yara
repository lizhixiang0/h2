/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSFraud - Whiskey co
    Rule id: 799
    Created at: 2015-08-26 08:01:48
    Updated at: 2015-11-05 09:47:25
    
    Rating: #0
    Total detections: 48402
*/

import "androguard"


rule SMSFraud
{


	condition:
		
		androguard.certificate.issuer(/\/C=UK\/ST=Portland\/L=Portland\/O=Whiskey co\/OU=Whiskey co\/CN=John Walker/)
		
}
