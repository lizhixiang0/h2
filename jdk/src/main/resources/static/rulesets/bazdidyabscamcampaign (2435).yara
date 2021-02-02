/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: silverfoxy
    Rule name: bazdidyabScamCampaign
    Rule id: 2435
    Created at: 2017-04-08 19:13:23
    Updated at: 2017-04-09 15:54:07
    
    Rating: #0
    Total detections: 5
*/

import "androguard"

rule bazdidyabScamCampaign
{
	meta:
		description = "A sample from Scam and Mass Advertisement campaign spreading their scamware over telegram, making money by scamming users and adding them to mass advertisement channels in Telegram"
		sample = "c3b550f707071664333ac498d1f00d754c29a8216c9593c2f51a8180602a5fab"

	condition:
		androguard.url(/^https?:\/\/([\w\d]+\.)?bazdidyabtelgram\.com\/?.*$/)
}
