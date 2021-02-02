/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: HackedScreen
    Rule id: 557
    Created at: 2015-06-04 08:56:31
    Updated at: 2015-08-06 15:45:26
    
    Rating: #0
    Total detections: 3303
*/

//Probably Android.Adware.Mulad

import "androguard"

rule HackedScreen
{
    condition:
        androguard.activity(/.*\.HackedScreen/)
}
