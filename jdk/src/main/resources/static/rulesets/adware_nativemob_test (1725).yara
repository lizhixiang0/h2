/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Gaurav
    Rule name: Adware_Nativemob_test
    Rule id: 1725
    Created at: 2016-08-04 12:54:49
    Updated at: 2016-08-12 12:06:05
    
    Rating: #0
    Total detections: 293
*/

import "androguard"
import "file"
import "cuckoo"


rule koodous : official
{
	meta:
		description = "Adware showing full-screen ads even if infected app is closed"
		sample = "0e18c6a21c33ecb88b2d77f70ea53b5e23567c4b7894df0c00e70f262b46ff9c"
		ref_link = "http://news.drweb.com/show/?i=10115&c=38&lng=en&p=0"

	strings:
		$a = "com/nativemob/client/" // Ad-network library

	condition:
		all of them
		
}
