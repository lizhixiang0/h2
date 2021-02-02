/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: subscription
    Rule id: 876
    Created at: 2015-09-29 22:03:01
    Updated at: 2015-09-29 22:03:58
    
    Rating: #0
    Total detections: 793
*/

import "androguard"



rule subscript
{
	meta:
		description = "Coonecting to one of those sites (Splitting ',') and getting the user into a subscription."
		

	strings:
		$a = "fapecalijobutaka.biz,ymokymakyfe.biz,kugoheba.biz"

	condition:
		$a 
		
}
