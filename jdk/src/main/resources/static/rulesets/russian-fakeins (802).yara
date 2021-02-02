/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Russian FakeIns
    Rule id: 802
    Created at: 2015-08-27 09:23:08
    Updated at: 2015-08-27 09:24:47
    
    Rating: #0
    Total detections: 75866
*/

import "androguard"


rule fakeInstaller
{
	meta:
		description = "The apps developed by this guy are fakeinstallers"
		one_sample = "fb20c78f51eb781d7cce77f501ee406a37327145cf43667f8dc4a9d77599a74d"

	condition:
		androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")
		
}
