/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: oguzhantopgul
    Rule name: Android Clicker Variant
    Rule id: 776
    Created at: 2015-08-11 12:03:22
    Updated at: 2016-02-08 13:42:08
    
    Rating: #1
    Total detections: 98
*/

import "androguard"


rule clicker : urls
{
	meta:
		description = "This rule detects the android clicker variat"
		sample = "b855bcb5dcec5614844e0a49da0aa1782d4614407740cb9d320961c16f9dd1e7"

	condition:
		androguard.url(/bestmobile\.mobi/) or 
		androguard.url(/oxti\.org/) or
		androguard.url(/oxti\.net/) or
		androguard.url(/oin\.systems/) or 
		androguard.url(/wallpapers535\.in/) or 
		androguard.url(/pop\.oin\.systems/)
}
