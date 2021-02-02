/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: Adware - protank
    Rule id: 1815
    Created at: 2016-09-16 10:10:51
    Updated at: 2016-09-16 10:17:09
    
    Rating: #0
    Total detections: 479
*/

import "androguard"


rule protank_url : adware
{
	meta:
		description = ""
		sample = ""

	condition:
		androguard.url(/pro-tank-t34\.ru/) 

}

rule protank_package_name : adware
{
	meta:
		description = ""
		sample = ""

	condition:
		androguard.app_name("PlayMob Market")

}
