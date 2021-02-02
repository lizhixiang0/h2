/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: FaKeAV
    Rule id: 643
    Created at: 2015-06-29 10:39:46
    Updated at: 2015-08-06 15:20:38
    
    Rating: #0
    Total detections: 8299
*/

import "androguard"

rule fakeav
{

	condition:
	  androguard.package_name("com.hao.sanquanweishi") or
	  androguard.certificate.sha1("1C414E5C054136863B5C460F99869B5B21D528FC")
}
