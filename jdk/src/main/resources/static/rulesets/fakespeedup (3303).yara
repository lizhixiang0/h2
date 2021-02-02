/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: FakeSpeedUp
    Rule id: 3303
    Created at: 2017-08-03 07:23:14
    Updated at: 2017-08-03 07:43:50
    
    Rating: #0
    Total detections: 144
*/

import "androguard"


rule rest
{
	strings:
		$ = "cards, you can resolve the confusion within your heart. Every card has two" 
	  	$ = "sides, representing the Pros and Cons of a subject. All the answers are" 
		$ = "First of all, this is a free software, but due to the high development costs" 

	condition:
		all of them
		
}
