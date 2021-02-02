/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: BaiduPacker
    Rule id: 1588
    Created at: 2016-07-07 15:38:12
    Updated at: 2016-07-08 13:29:49
    
    Rating: #0
    Total detections: 7771
*/

rule packers : baidu
{
	meta:
		description = "This rule detects packers based on files used by them"
		

	strings:
		$baidu_1 = "libbaiduprotect.so"
		$baidu_2 = "baiduprotect.jar"
		$baidu_3= "libbaiduprotect_x86.so"

	condition:
		all of them
		
}
