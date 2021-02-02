/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: DirtyGirl
    Rule id: 3269
    Created at: 2017-07-28 16:56:01
    Updated at: 2017-08-16 14:19:41
    
    Rating: #0
    Total detections: 64932
*/

import "androguard"
import "file"
import "cuckoo"


rule DirtyGirl
{
	meta:
		description = "This rule detects dirtygirl samples"
		sample = "aeed925b03d24b85700336d4882aeacc"
		
	condition:
		androguard.service(/com\.door\.pay\.sdk\.sms\.SmsService/) or
		androguard.url(/120\.26\.106\.206/)

}
