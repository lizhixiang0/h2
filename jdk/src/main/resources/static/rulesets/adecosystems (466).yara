/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: adecosystems
    Rule id: 466
    Created at: 2015-05-06 12:49:05
    Updated at: 2015-08-06 16:00:18
    
    Rating: #0
    Total detections: 89118
*/

import "cuckoo"

rule adecosystems
{
    condition:
 		cuckoo.network.http_request(/ads01\.adecosystems\.com/) or cuckoo.network.http_request(/ads02\.adecosystems\.com/) or cuckoo.network.http_request(/ads03\.adecosystems\.com/) or cuckoo.network.http_request(/ads04\.adecosystems\.com/)
}
