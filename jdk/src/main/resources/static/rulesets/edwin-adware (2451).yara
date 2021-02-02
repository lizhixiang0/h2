/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Edwin adware
    Rule id: 2451
    Created at: 2017-04-12 18:03:29
    Updated at: 2017-04-12 18:32:57
    
    Rating: #0
    Total detections: 5821
*/

import "androguard"

rule edwin : malware
{
	meta:
		description = "edwin adware"
		sample = "6316b74bc4ee0457ed0b0bbe93b082c2081d59e0b8e0bf6022965b0c5a42ea94"
		url_report = "http://researchcenter.paloaltonetworks.com/2017/04/unit42-ewind-adware-applications-clothing/"

	condition:
		(androguard.activity(/b93478b8cdba429894e2a63b70766f91.ads/i) or
		androguard.activity(/delete.off/i)) and
		androguard.certificate.sha1("405E03DF2194D1BC0DDBFF8057F634B5C40CC2BD")
		
		
}
