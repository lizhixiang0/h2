/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kiya
    Rule name: joker
    Rule id: 5973
    Created at: 2019-10-17 06:59:20
    Updated at: 2019-10-17 07:01:39
    
    Rating: #0
    Total detections: 0
*/

rule android_joker {     
    strings:
        $net = { 2F6170692F636B776B736C3F6963633D } // /api/ckwksl?icc=   
        $ip = "3.122.143.26"
    condition:
        $net or $ip 
}
