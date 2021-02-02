/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: flopez
    Rule name: Shiny adware
    Rule id: 477
    Created at: 2015-05-07 11:06:57
    Updated at: 2015-08-06 15:20:05
    
    Rating: #1
    Total detections: 5007
*/

import "androguard"
import "cuckoo"

rule shiny_adware
{
	condition:
		androguard.package_name(/com.shiny*/) and cuckoo.network.http_request(/http:\/\/fingertise\.com/)
}
