/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Fake_GoogleChrome
    Rule id: 1559
    Created at: 2016-07-02 17:19:28
    Updated at: 2016-07-02 17:20:32
    
    Rating: #0
    Total detections: 1531
*/

import "androguard"


rule fake_google_chrome
{
	meta:
		description = "This rule detects fake google chrome apps"
		sample = "ac8d89c96e4a7697caee96b7e9de63f36967f889b35b83bb0fa5e6e1568635f5"

	condition:
		androguard.package_name("com.android.chro.me")
		
}
