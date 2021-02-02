/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: MilkyDoor
    Rule id: 2558
    Created at: 2017-04-25 09:50:56
    Updated at: 2017-04-25 10:29:36
    
    Rating: #0
    Total detections: 38
*/

import "androguard"

rule MilkyDoor {
	meta:
		description = "http://blog.trendmicro.com/trendlabs-security-intelligence/operation-c-major-actors-also-used-android-blackberry-mobile-spyware-targets/"
	
	strings:
	  	$ = /144.76.108.61/
		$ = /hgnhpmcpdrjydxk.com/
		$ = /jycbanuamfpezxw.com/
		$ = /liketolife.com/
		$ = /milkyapps.net/
		$ = /soaxfqxgronkhhs.com/
		$ = /uufzvewbnconiyi.com/
		$ = /zywepgogksilfmc.com/

	condition:
		1 of them

}
