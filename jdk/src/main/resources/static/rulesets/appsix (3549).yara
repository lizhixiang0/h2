/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: App.Six
    Rule id: 3549
    Created at: 2017-09-05 07:44:43
    Updated at: 2017-09-05 07:53:52
    
    Rating: #0
    Total detections: 261
*/

import "androguard"

rule appsix
{
    strings:
		$a1 = "cvc_visa" 
		$a2 = "controller.php"  
		$a3 = "mastercard" 
	condition:
        androguard.package_name(/app.six/) and 
		2 of ($a*)
}
