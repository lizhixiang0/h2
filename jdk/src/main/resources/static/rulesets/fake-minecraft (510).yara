/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Fake Minecraft
    Rule id: 510
    Created at: 2015-05-23 12:13:58
    Updated at: 2015-08-06 15:20:07
    
    Rating: #0
    Total detections: 3423
*/

import "androguard"

rule minecraft
{
	condition:
		( androguard.app_name("Minecraft: Pocket Edition") or 
			androguard.app_name("Minecraft - Pocket Edition") )
		and not androguard.package_name("com.mojang.minecraftpe")
}
