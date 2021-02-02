/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: FakeBank_Fanta
    Rule id: 1627
    Created at: 2016-07-14 12:21:31
    Updated at: 2016-07-14 12:24:31
    
    Rating: #0
    Total detections: 301
*/

import "androguard"

rule Android_FakeBank_Fanta
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android FakeBank_Fanta"
		source = "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/"

	condition:
		androguard.service(/SocketService/i) and 
		androguard.receiver(/MyAdmin/i) and 
		androguard.receiver(/Receiver/i) and 
		androguard.receiver(/NetworkChangeReceiver/i)
		
}
