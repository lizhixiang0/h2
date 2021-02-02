/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: FakeCMSecurity
    Rule id: 2331
    Created at: 2017-03-14 13:06:15
    Updated at: 2017-03-14 13:07:46
    
    Rating: #0
    Total detections: 197
*/

import "androguard"

rule FakeCMSecurity: Certs
{
    condition:
        androguard.certificate.sha1("2E66ED3E9EE51D09A8EFCE00D32AE5E078F1F1B6")
        
}
