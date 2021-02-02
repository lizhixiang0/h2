/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: Fraudulent Developers
    Rule id: 666
    Created at: 2015-07-07 10:25:18
    Updated at: 2015-08-06 15:20:52
    
    Rating: #0
    Total detections: 1090
*/

import "androguard"

rule fraudulent_developers : airpush
{
	condition:
		androguard.certificate.issuer(/tegyhman/) 
		or androguard.certificate.issuer(/tengyhman/)
		or androguard.certificate.issuer(/pitorroman/) 
		or androguard.certificate.subject(/pitorroman/)
}
