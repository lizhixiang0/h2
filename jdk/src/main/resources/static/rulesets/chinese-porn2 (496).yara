/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Chinese Porn2
    Rule id: 496
    Created at: 2015-05-14 12:00:57
    Updated at: 2015-08-06 16:00:38
    
    Rating: #0
    Total detections: 36271
*/

import "androguard"

rule chinese2 : sms_sender
{
	condition:
		androguard.package_name(/com.adr.yykbplayer/) or 
		androguard.package_name(/sdej.hpcite.icep/) or
		androguard.package_name(/p.da.wdh/) or
		androguard.package_name(/com.shenqi.video.sjyj.gstx/) or
		androguard.package_name(/cjbbtwkj.xyduzi.fa/) or
		androguard.package_name(/kr.mlffstrvwb.mu/)
}
