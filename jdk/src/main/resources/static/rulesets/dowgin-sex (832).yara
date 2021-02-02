/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Dowgin-sex
    Rule id: 832
    Created at: 2015-09-18 05:46:43
    Updated at: 2015-09-18 05:52:13
    
    Rating: #0
    Total detections: 359
*/

rule dowgin
{
	meta:
		sample = "13d63521e989be22b81f21bd090f325688fefe80e7660e57daf7ca43c31105cb"
		sample2 = "8840f0e97b7909c8fcc9c61cdf6049d08dc8153a58170976ff7087e25461d7bd"
		sample3 = "14f40c998a68d26a273eba54e1616a1a1cd77af4babb0f159a228754d3fd93ba"
		sample4 = "ad8803481b08f6d7bea92a70354eca504da73a25df3e52b0e028b1b125d9a6be"
		sample5 = "243c4042d8b0515cbb88887432511611fc5aa25e1d719d84e96fd44613a3e0cc"

	strings:
		$a = "SexPoseBoxLayout"
		$b = "PleasureStartsLayout"
		$c = "lYttxRF!2"

	condition:
		all of them
		
}
