/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: AirPush.Adware
    Rule id: 685
    Created at: 2015-07-13 10:47:04
    Updated at: 2016-02-08 11:25:42
    
    Rating: #2
    Total detections: 173195
*/

rule AirPush
{
	meta:
        description = "Evidences of AirPush Adware SDK. v1.2 20160208"
	strings:
    	$1 = "AirpushAdActivity.java"
    	$2 = "&airpush_url="
		$3 = "getAirpushAppId"
		$4 = "Airpush SDK is disabled"
		$5 = "api.airpush.com/dialogad/adclick.php"
		$6 = "res/layout/airpush_notify.xml"
		$7 = "Airpush Ads require Android 2.3"
		$8 = "AirpushInlineBanner"
		$9 = "AirpushAdEntity"
   	condition:
    	1 of them
}
