/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Xavier
    Rule id: 2982
    Created at: 2017-06-13 12:58:44
    Updated at: 2017-06-13 13:03:48
    
    Rating: #0
    Total detections: 27
*/

import "androguard"



rule Xavier : basic
{
	meta:
		description = "This rule detects the Xavier malicious ad library"
		sample = "6013393b128a4c6349b48f1d64c55aa14477e28cc747b57a818e3152915b14cc/analysis"
		reference = "http://thehackernews.com/2017/06/android-google-play-app-malware.html"



	condition:
		androguard.activity("xavier.lib.XavierActivity") and
		androguard.service("xavier.lib.message.XavierMessageService")
		
}
