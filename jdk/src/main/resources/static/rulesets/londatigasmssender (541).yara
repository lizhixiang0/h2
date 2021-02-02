/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: Londatiga:SMSSender
    Rule id: 541
    Created at: 2015-06-02 13:20:47
    Updated at: 2015-08-06 15:20:11
    
    Rating: #0
    Total detections: 61698
*/

import "androguard"

//SMSSender
rule londatiga
{
	condition:
		androguard.certificate.sha1("ECE521E38C5E9CBEA53503EAEF1A6DDD204583FA")
}
