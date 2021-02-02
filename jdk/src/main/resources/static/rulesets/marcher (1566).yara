/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: Marcher
    Rule id: 1566
    Created at: 2016-07-04 15:59:05
    Updated at: 2018-07-30 11:03:27
    
    Rating: #0
    Total detections: 969
*/

import "androguard"

rule Android_Marcher
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "04-July-2016"
		description = "Marcher has been active since 2013; like any commercial malware, it is featured in different campaigns, in multiple countries."
		source = "https://exchange.xforce.ibmcloud.com/collection/Marcher-Android-Bot-eeede463ee5c2b57402fc86154411e65"

	condition:
		(androguard.filter(/com.KHLCert.fdservice/i) and
		androguard.filter(/com.KHLCert.gpservice/i))
}
