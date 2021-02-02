/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: OmniRat
    Rule id: 1682
    Created at: 2016-07-26 10:33:47
    Updated at: 2016-07-26 10:34:42
    
    Rating: #0
    Total detections: 30
*/

import "androguard"

rule OmniRat: Certs
{
    condition:
        androguard.certificate.sha1("B17BACFB294A2ADDC976FE5B8290AC27F31EB540")
        
}
