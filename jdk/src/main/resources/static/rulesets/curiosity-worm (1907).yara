/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Diviei
    Rule name: Curiosity worm
    Rule id: 1907
    Created at: 2016-10-13 08:30:05
    Updated at: 2016-10-13 10:41:01
    
    Rating: #0
    Total detections: 141
*/

rule curiosity
{
	meta:
		description = "Curiosity malware"
		sample = "481eef57626aceff65671e7985285f0f43def22b6007880af87d7fd1f4e12d64"
		source = "http://blog.avlsec.com/2016/10/3849/worm/"

	strings:
		$a = {4b 48 65 6c 6c 6f 20 49 20 66 6f 75 6e 64 20 79 6f 75 72 20 70 72 69 76 61 74 65 20 70 68 6f 74 6f 73 20 68 65 72 65}
		$b = {45 75 20 65 6e 63 6f 6e 74 72 65 69 20 73 75 61 73 20 66 6f 74 6f 73 20 70 72 69 76 61 64 61 73 20 61 71 75 69}
		$c = {53 42 6f 6e 6a 6f 75 72 20 6a 61 69 20 74 72 6f 75 76}
		$d = {6b 69 6e 67 73 74 61 72 62 6f 79 40 6f 75 74 6c 6f 6f 6b 2e 63 6f 6d}
		$e = {76 64 73 6f 66 74 2e 73 70 79 69 6e 67 2e 73 6a 69 6e 2e 70 65 72 6d 69 73 73 69 6f 6e 2e 43 32 44 5f 4d 45 53 53 41 47 45}

	condition:
		all of them
}
