/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Dropper
    Rule id: 1560
    Created at: 2016-07-03 09:57:02
    Updated at: 2016-07-05 14:05:41
    
    Rating: #1
    Total detections: 14699
*/

rule dropper
{
	meta:
		description = "This rule detects a dropper app"
		sample = "6c0216b7c2bffd25a4babb8ba9c502c161b3d02f3fd1a9f72ee806602dd9ba3b"
		sample2 = "0089123af02809d73f299b28869815d4d3a59f04a1cb7173e52165ff03a8456a"
		

	strings:
		$a = "Created-By: Android Gradle 2.0.0"
		$b = "UnKnown0"
		$c = "UnKnown1"
		$d = "Built-By: 2.0.0"
		//$e = "WallpaperService" wide


	condition:
		all of them
}
