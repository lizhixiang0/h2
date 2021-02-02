/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: New Ruleset
    Rule id: 875
    Created at: 2015-09-29 21:50:19
    Updated at: 2015-09-29 21:52:09
    
    Rating: #0
    Total detections: 6418
*/

import "androguard"



rule rusSMS
{
	meta:
		description = "Russian app, connects to remote server (http://googlesyst.com/) and gets the user to answer SMS (and a fake funds balance). Apparently, to unlock the app you have to send reiterate SMS."

	strings:
		// Both domains (GoogleSyst is not official afaik. registered on the same place)
		$a = "http://googlesyst.com/"
		$b = "mxclick.com"

	condition:
		$a and $b
		
}
