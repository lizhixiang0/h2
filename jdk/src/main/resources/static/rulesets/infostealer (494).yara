/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: InfoStealer
    Rule id: 494
    Created at: 2015-05-13 18:53:55
    Updated at: 2015-08-06 15:20:05
    
    Rating: #0
    Total detections: 4686
*/

import "androguard"

//ss (com.samples.servicelaunch)
//Developer: cows lab
rule InfoStealer
{
	//Sample: 695fafc2c8e310876dbb6cd219eb0a6728cc342c5ff358923b00455e34e2753b
	condition:
		//androguard.certificate.sha1("933FAAD48C56B8B2218F114CD0F4EC9D0386825D") and
		androguard.package_name(/com.samples.servicelaunch/) and
		androguard.app_name(/ss/)
}
