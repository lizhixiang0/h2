/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: apozuelo
    Rule name: apozuelo slempo
    Rule id: 2814
    Created at: 2017-05-29 20:00:18
    Updated at: 2017-05-29 20:21:35
    
    Rating: #0
    Total detections: 72
*/

rule slempo_detectado
{
        meta:
                description = "Trojan-Banker.Slempo"

        strings:
                $a = "org/slempo/service" nocase


        condition:
                1 of them
}
