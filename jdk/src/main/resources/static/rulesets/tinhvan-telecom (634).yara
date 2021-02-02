/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Tinhvan Telecom
    Rule id: 634
    Created at: 2015-06-26 10:28:10
    Updated at: 2015-08-06 15:20:37
    
    Rating: #0
    Total detections: 4767
*/

import "androguard"


rule tinhvan
{
	meta:
		sample = "0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5"

	condition:
		androguard.certificate.sha1("0DFBBDB7735517748C3DEF3B6DEC2A800182D1D5")
		
}
