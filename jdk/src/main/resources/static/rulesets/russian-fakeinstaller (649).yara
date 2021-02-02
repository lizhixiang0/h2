/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Russian FakeInstaller
    Rule id: 649
    Created at: 2015-07-01 09:18:50
    Updated at: 2015-08-06 15:20:52
    
    Rating: #0
    Total detections: 77870
*/

import "androguard"


rule russian : fakeInst
{

	condition:
		
		androguard.certificate.sha1("D7FE504792CD5F67A7AF9F26C771F990CA0CB036")
		
}
