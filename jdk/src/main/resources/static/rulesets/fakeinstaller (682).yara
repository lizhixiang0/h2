/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: FakeInstaller
    Rule id: 682
    Created at: 2015-07-10 14:20:23
    Updated at: 2015-08-06 15:45:37
    
    Rating: #2
    Total detections: 80243
*/

import "androguard"
import "cuckoo"


rule fakeinstaller
{
	meta:
		sample = "e39632cd9df93effd50a8551952a627c251bbf4307a59a69ba9076842869c63a"

	condition:
		androguard.permission(/com.android.launcher.permission.INSTALL_SHORTCUT/)
		and androguard.permission(/android.permission.SEND_SMS/)
		and androguard.certificate.sha1("E030A31BE312FF938AAF3F314934B1E92AF25D60")
		and androguard.certificate.issuer(/hghjg/)
}
