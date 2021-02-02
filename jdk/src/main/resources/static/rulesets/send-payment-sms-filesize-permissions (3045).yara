/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Sarcares
    Rule name: Send Payment SMS - Filesize & Permissions
    Rule id: 3045
    Created at: 2017-06-26 13:26:14
    Updated at: 2017-07-04 01:05:41
    
    Rating: #0
    Total detections: 13
*/

import "androguard"
import "file"

rule Size_and_Permissions: smsfraud
{
	meta:
		description = "This rule should match applications that send SMS"
		cluster = "Type 2"
		sample1 = "d1860ea0d9c4cb70b1a73789939a3f310eb48741111132d44283ab71a424b773"
		sample2 = "c9026fee9f82e43e53c1f385ac99b427a3f4e41a5fe874275a8c80a41762aad8"
		sample3 = "136b92e2eb57a02692c06a22e1596f6fbedb6a78b14475a1ebac929b1bb57013"

	condition:
		file.size <= 5MB //and file.size >= 1MB (?)
		and androguard.number_of_permissions >= 90
		and androguard.permission(/(SEND|WRITE)_SMS/)
		and androguard.functionality.run_binary.code(/invoke-static v0, Ljava\/lang\/System;->loadLibrary(Ljava\/lang\/String;)V/)

		// and	androguard.functionality.run_binary.method("clinit") (?)
}
