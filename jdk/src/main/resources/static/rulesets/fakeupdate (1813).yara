/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: FakeUpdate
    Rule id: 1813
    Created at: 2016-09-15 11:17:48
    Updated at: 2016-09-15 11:19:42
    
    Rating: #0
    Total detections: 78
*/

import "androguard"

rule FakeUpdate
{
    condition:
        androguard.certificate.sha1("45167886A1C3A12212F7205B22A5A6AF0C252239")
        
        
}
