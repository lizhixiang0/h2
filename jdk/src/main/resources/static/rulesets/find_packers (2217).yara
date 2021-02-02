/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: rocky
    Rule name: FIND_PACKERS
    Rule id: 2217
    Created at: 2017-02-06 12:51:13
    Updated at: 2017-02-06 13:12:48
    
    Rating: #0
    Total detections: 42808
*/

import "androguard"
import "file"
import "cuckoo"

rule qihoo360 : packer
{
	meta:
		description = "Qihoo 360"

	strings:
		$a = "libprotectClass.so"
		
	condition:
		$a 
}

rule ijiami : packer
{
	meta:
		description = "Ijiami"
		
	strings:
		$old_dat = "assets/ijiami.dat"
		$new_ajm = "ijiami.ajm"
		$ijm_lib = "assets/ijm_lib/"
		
	condition:
		$old_dat or $new_ajm or $ijm_lib
}

rule naga : packer
{
	meta:
		description = "Naga"
		
	strings:
		$lib = "libddog.so"
		
	condition:
		 $lib
}


rule alibaba : packer
{
	meta:
		description = "Alibaba"
		
	strings:
		$lib = "libmobisec.so"
		
	condition:
		 $lib
}

rule medusa : packer
{
	meta:
		description = "Medusa"

	strings:
		$lib = "libmd.so"

	condition:
		$lib
}

rule baidu : packer
{
	meta:
		description = "Baidu"
		
	strings:
		$lib = "libbaiduprotect.so"
		$encrypted = "baiduprotect1.jar"
		
	condition:
		$lib or $encrypted
}

rule pangxie : packer
{
	meta:
		description = "PangXie"
	
	strings:
		$lib = "libnsecure.so"
		
	condition:
	 	$lib
}
