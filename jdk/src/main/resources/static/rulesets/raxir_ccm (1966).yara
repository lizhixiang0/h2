/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Raxir_ccm
    Rule id: 1966
    Created at: 2016-11-17 21:11:28
    Updated at: 2016-11-17 21:17:45
    
    Rating: #0
    Total detections: 1547
*/

rule Raxir : ccm
{
        meta:
        description = "This rule was produced by CreateYaraRule and CommonCode, it detects RAXIR string decription routine"
        author = "_hugo_gonzalez_ "
		sample = "07278c56973d609caa5f9eb2393d9b1eb41964d24e7e9e7a7e7f9fdfb2bb4c31"
/*		source_ code = 
Lcom/google/gson/JsonNull; 
================================================== 
('concat', '36') 									
----------------------------------------			
public static String concat(int p7, String p8)		
    {												
        v0 = (p7 - 7);								
        v4 = p8.toCharArray();						
        v5 = v4.length;								
        v2 = v0;									
        v0 = 0;										
        while (v0 != v5) {							
            v6 = ((v2 & 95) ^ v4[v0]);				
            v3 = (v2 + 9);							
            v2 = (v0 + 1);							
            v4[v0] = ((char) v6);					
            v0 = v2;								
            v2 = v3;								
        }											
        return String.valueOf(v4, 0, v5).intern();
    }												
*/
		
        strings :
    
		$S_8_12_72 = { 12 01 d8 00 ?? ?? 6e 10 ?? ?? ?? 00 0c 04 21 45 01 02 01 10 32 50 11 00 49 03 04 00 dd 06 02 5f b7 36 d8 03 02 ?? d8 02 00 01 8e 66 50 06 04 00 01 20 01 32 28 f0 71 30 ?? ?? 14 05 0c 00 6e 10 ?? ?? 00 00 0c 00 11 00 }

    
    condition:
        all of them
}
