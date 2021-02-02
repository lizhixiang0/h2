/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: HiddenDeviceAdmin
    Rule id: 2492
    Created at: 2017-04-19 13:32:10
    Updated at: 2017-04-19 13:38:47
    
    Rating: #2
    Total detections: 10318
*/

import "androguard"

rule experimental
{
 
	strings:
		$ = "Th.Dlg.Fll13" nocase
		$ = "alluorine.info" nocase
		$ = "mancortz.info" nocase
		$ = "api-profit.com" nocase
		$ = "narusnex.info" nocase
		$ = "ronesio.xyz" nocase
		$ = "alluorine.info" nocase
		$ = "meonystic.info" nocase
		$ = "api-profit.com" nocase
		$ = "narusnex.info" nocase
		$ = "ngkciwmnq.info" nocase
		$ = "golangwq.info" nocase
		$ = "krnwhyvq.info" nocase
		$ = "nvewpvnid.info" nocase
		$ = "ovnwislxf.info" nocase
		$ = "deputizem.info" nocase
		
	condition:
		1 of them

}
