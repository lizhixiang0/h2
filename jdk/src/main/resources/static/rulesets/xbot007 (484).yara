/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: xbot007
    Rule id: 484
    Created at: 2015-05-11 10:44:58
    Updated at: 2015-08-06 15:20:05
    
    Rating: #0
    Total detections: 2213
*/

rule xbot007
{
	meta:
		source = "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"

	strings:
		$a = "xbot007"

	condition:
		any of them
}
