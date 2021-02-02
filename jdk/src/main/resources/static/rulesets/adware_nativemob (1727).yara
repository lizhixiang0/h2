/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Gaurav
    Rule name: Adware_Nativemob
    Rule id: 1727
    Created at: 2016-08-04 16:03:23
    Updated at: 2016-08-04 16:07:54
    
    Rating: #0
    Total detections: 148
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

		

	condition:
		androguard.receiver(/com\.nativemob\.client\.NativeEventReceiver/)
		
}
