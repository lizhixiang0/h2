/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: Dropper
    Rule id: 3040
    Created at: 2017-06-25 14:02:57
    Updated at: 2018-06-04 00:58:04
    
    Rating: #0
    Total detections: 8646
*/

import "androguard"

rule SMSFraude
{
	meta:
		autor = "sadfud"
		description = "Se conecta a un panel desde el que descarga e instala nuevas aplicaciones"
	condition:
		androguard.url(/app\.yx93\.com/)		
}
