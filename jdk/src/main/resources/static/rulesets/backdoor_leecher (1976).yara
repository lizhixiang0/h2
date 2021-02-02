/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Backdoor_Leecher
    Rule id: 1976
    Created at: 2016-11-23 06:59:58
    Updated at: 2016-11-23 07:01:20
    
    Rating: #0
    Total detections: 650
*/

import "androguard"

rule Leecher_A
{
    condition:
        androguard.certificate.sha1("B24C060D41260C0C563FEAC28E6CA1874A14B192")
}
