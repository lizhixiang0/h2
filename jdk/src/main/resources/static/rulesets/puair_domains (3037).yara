/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: PUA.IR_DOMAINS
    Rule id: 3037
    Created at: 2017-06-23 10:22:20
    Updated at: 2017-06-23 10:25:43
    
    Rating: #0
    Total detections: 26
*/

import "androguard"



rule khashayar_talebi
{
	meta:
		description = "Possible Threats, Domains registered for khashayar.talebi@yahoo.com"


	strings:
		$ = "tmbi.ir"
		$ = "masirejavan.ir"
		$ = "clipmobile.ir"
		$ = "razmsport.ir"
		$ = "norehedayat.ir"
		$ = "dlappdev.ir"
		$ = "telememberapp.ir"
		$ = "btl.ir"
		$ = "niazeparsi.ir"
		$ = "imdbfa.ir"
		$ = "thecars.ir"
		$ = "rahaserver.ir"
		$ = "mehrayen.ir"

	condition:
		1 of them
		
}
