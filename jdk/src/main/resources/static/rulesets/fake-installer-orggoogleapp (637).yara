/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Fake installer (org.google.app)
    Rule id: 637
    Created at: 2015-06-26 12:36:17
    Updated at: 2015-08-06 15:20:37
    
    Rating: #0
    Total detections: 1873
*/

import "androguard"

rule fake_installer: orggoogleapp
{
	condition:
		androguard.certificate.sha1("86718264E68A7A7C0F3FB6ECCB58BEC546B33E22")				
}
