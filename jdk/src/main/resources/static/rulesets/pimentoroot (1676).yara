/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: acgmohu
    Rule name: PimentoRoot
    Rule id: 1676
    Created at: 2016-07-25 12:45:00
    Updated at: 2016-07-25 12:46:31
    
    Rating: #0
    Total detections: 24777
*/

import "androguard"


rule PimentoRoot : rootkit
{
	condition:
		androguard.url(/http:\/\/webserver\.onekeyrom\.com\/GetJson\.aspx/)
		
}
