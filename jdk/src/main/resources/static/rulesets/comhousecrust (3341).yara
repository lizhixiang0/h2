/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: com.house.crust
    Rule id: 3341
    Created at: 2017-08-08 10:44:49
    Updated at: 2017-08-08 10:51:41
    
    Rating: #0
    Total detections: 816
*/

import "androguard"


rule com_house_crust
{
		strings:
			$a = "assets/com.jiahe.school.apk" nocase
		condition:
		androguard.package_name("com.house.crust") or
		androguard.certificate.sha1("E1DF7A92CE98DC2322C7090F792818F785441416") and
		$a
		
}
