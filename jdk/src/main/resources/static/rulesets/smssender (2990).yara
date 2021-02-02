/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: roskyfrosky
    Rule name: SMSSender
    Rule id: 2990
    Created at: 2017-06-14 14:01:40
    Updated at: 2017-06-16 05:46:19
    
    Rating: #0
    Total detections: 2011
*/

import "androguard"
import "file"
import "cuckoo"


rule smssender_FakeAPP
{

	condition:
		androguard.certificate.sha1("405E03DF2194D1BC0DDBFF8057F634B5C40CC2BD") or 
		androguard.package_name("test.app") or 
		androguard.receiver("b93478b8cdba429894e2a63b70766f91.ads.Receiver")
}


rule SMSFraud
{
	condition:
		androguard.certificate.sha1("003274316DF850853687A26FCA9569A916D226A0") or 
		androguard.package_name("com.googleapi.cover") or 
		androguard.package_name("ru.android.apps")

}
