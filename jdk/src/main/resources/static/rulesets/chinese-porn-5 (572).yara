/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Chinese porn 5
    Rule id: 572
    Created at: 2015-06-08 21:37:54
    Updated at: 2015-08-06 15:20:14
    
    Rating: #0
    Total detections: 13289
*/

import "androguard"

rule chineseporn5 : SMSSend
{

	condition:
		androguard.package_name("com.shenqi.video.ycef.svcr") or 
		androguard.package_name("dxas.ixa.xvcekbxy") or
		androguard.package_name("com.video.ui") or 
		androguard.package_name("com.qq.navideo") or
		androguard.package_name("com.android.sxye.wwwl") or
		androguard.certificate.issuer(/llfovtfttfldddcffffhhh/)
		
}
