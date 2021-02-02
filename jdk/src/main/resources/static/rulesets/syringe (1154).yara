/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Syringe
    Rule id: 1154
    Created at: 2016-01-25 06:42:58
    Updated at: 2016-04-14 12:42:52
    
    Rating: #0
    Total detections: 2352
*/

rule syringe
{
	strings:
		$a = "setHostService"
		$b = "getHostActivity"
		$c = "MainApplication.java"
		$d = "kqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwqAFW0sDGPfZ9GxASIFGcdrCdHefFdCjmB4c5M9RADKikKYlD9LjjlTtcTfP6MBMUGayzgDAI0Tt4oqLI1//DddfIFCQ4eC2VTYiTsb+dx23GT5wERpaN2T+1cbZG9aNL2TEkriuoN2ovIa6yXGMI8srqjlq9TP8djedzgRaStQl/zrjPz+G00FxfBObgfgTvzgaAvaluBXTnvu0N2t5KG0ubQC24d2dTrr+Kc9Y9ZiMqDTOn8rLgoM/PcJZkKg5d7GQMpNC1GJeWCcGh6NMhv3QGn/GswfW865AmyxL75JE+61Un8cxouTUQzEsGZ3zNR/F3tA0SKyQCl7LwfV8dwIDAQ"

	condition:
		all of them
		
}
