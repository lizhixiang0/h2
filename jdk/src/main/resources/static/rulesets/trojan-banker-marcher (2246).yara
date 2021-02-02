/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Trojan Banker Marcher
    Rule id: 2246
    Created at: 2017-02-15 10:01:32
    Updated at: 2017-05-08 14:10:39
    
    Rating: #0
    Total detections: 8
*/

rule Trojan_Banker4:Marcher {

	strings:
		$ = "a!v!g.!a!n!t!i!vi!ru!s"
		$ = "a!vg!.!a!n!t!i!v!i!r!u!s"
		$ = "a!vg!.an!ti!vi!r!us!"
		$ = "a!vg.a!n!t!i!v!irus!"
		$ = "av!g!.!a!n!ti!v!i!r!us"
		$ = "av!g.!an!ti!v!i!ru!s!"
		$ = "a!vg.!a!nt!i!v!irus"
		$ = "avg!.!a!n!tivi!ru!s!"
		$ = "avg.!a!n!t!i!v!i!r!u!s"
		$ = "a!v!g.a!n!tiv!i!ru!s"
		

	condition:
		1 of ($)


}
