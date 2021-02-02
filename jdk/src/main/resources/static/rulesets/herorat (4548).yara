/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: HeroRat
    Rule id: 4548
    Created at: 2018-06-19 09:34:14
    Updated at: 2018-08-22 12:57:50
    
    Rating: #0
    Total detections: 191
*/

import "cuckoo"
import "droidbox"

rule herorat
{
	meta:
		description = "HeroRat"
		sample = "92edbf20549bad64202654bc51cc581f706a31bd8d877812b842d96406c835a1 3b40b5081c2326f70e44245db9986f7a2f07a04c9956d27b198b6fc0ae51b3a2 a002fca557e33559db6f1d5133325e372dd5689e44422297406e8337461e1548"

	condition:
		cuckoo.network.dns_lookup(/api.telegram.org/) and droidbox.written.filename(/sadas45sg6d4f6g696sadgfasdgf4/)
		
}
