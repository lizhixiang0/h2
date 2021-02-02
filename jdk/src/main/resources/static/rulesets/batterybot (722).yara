/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: BatteryBot
    Rule id: 722
    Created at: 2015-07-17 14:35:36
    Updated at: 2015-08-06 15:20:56
    
    Rating: #0
    Total detections: 81
*/

//http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html
import "androguard"


rule koodous : ClickFraud AdFraud SMS Downloader_Trojan
{
	meta:
		description = "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"
		sample = "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5"

	condition:

		androguard.activity(/com\.polaris\.BatteryIndicatorPro\.BatteryInfoActivity/i) and
		androguard.permission(/android\.permission\.SEND_SMS/)
		
}
