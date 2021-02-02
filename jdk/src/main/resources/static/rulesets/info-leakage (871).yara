/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: Info Leakage
    Rule id: 871
    Created at: 2015-09-28 20:17:18
    Updated at: 2015-09-28 20:19:09
    
    Rating: #0
    Total detections: 1310433
*/

import "androguard"


rule infoLeak
{
	meta:
		description = "Get user info (IP, IMEI, SMS...) sent to remote address. "
		

	strings:
		$a = "http://imgsx.lingte.cc:8080/MTProject/MTContr?action=MTDetial&id="
		$b = "http://count.lingte.cc/IsInterface.php"
		$c = "http://imgsx.lingte.cc:8080/MTProject/MTContr?action=MTListUp&typeid="


	condition:
		$a or $b or $c
		
}
