/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: HummingWhale
    Rule id: 2172
    Created at: 2017-01-24 09:52:33
    Updated at: 2017-01-24 10:04:51
    
    Rating: #0
    Total detections: 39
*/

rule HummingWhale
{
	meta:
		description = "A Whale of a Tale: HummingBad Returns, http://blog.checkpoint.com/2017/01/23/hummingbad-returns/"
		sample = "0aabea98f675b5c3bb0889602501c18f79374a5bea9c8a5f8fc3d3e5414d70a6"

	strings:
		$ = "apis.groupteamapi.com"
		$ = "app.blinkingcamera.com"
		
	condition:
 		1 of them
		
}
