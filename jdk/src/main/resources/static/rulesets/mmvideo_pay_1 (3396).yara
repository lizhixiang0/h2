/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: wushen
    Rule name: MMVideo_Pay_1
    Rule id: 3396
    Created at: 2017-08-17 07:39:34
    Updated at: 2017-08-17 07:41:10
    
    Rating: #0
    Total detections: 1469
*/

import "androguard"
import "file"
import "cuckoo"

/*
this is used to filter one of the MMVideo by its pay configuaration

public static final String BY_URL = "baiy/pay/wxScan";
public static final int EXCUTE_AGAIN = 400;
public static final String GZH_URL = "content/savePayInfo";
public static final String RONGHE_WAP = "http://pay.fzw988.com/apiTvShow/itf/getallurlbyname?name=scanandzfb";
public static final String SCAN_JUMP = "pages/paySuccess.jsp";
public static final String SCAN_QUERY = "content/commquery";
public static final String SCAN_REQUEST = "citicscan/wxscanUrl";
public static final String SCAN_REQUEST3 = "citicscan/wxscanUrl3";
public static final String SFT_NOTIFY = "ytwx/notify";
public static final String SFT_URL = "ytwx/wapPay";
public static final String TY_WXWAP_URL = "qixun/wxH5Pay";
public static final String URL_SELF = "citic/ali/scan";
public static final String XC_URL = "xiaoc/gwapPay";
public static final String XYT_URL = "xyt/gwappay";
public static final String ZX_URL = "zhongx/pay";
public static int requestOk;

static {
PayConfig.contact = "13120747542/2818147339";
PayConfig.prefixUrl = "http://pay.epgaclub.com/apiTvShow/";
PayConfig.gzhStart = "http://12.3.js.cn/tvr725.php";
PayConfig.selfWx = 0;

*/
rule MMVideo_Pay_1 : MMVideo
{
	meta:
		description = "this is used to filter one of the MMVideo by its pay configuaration"

	strings:
		$paycfg_0 = "baiy/pay/wxScan"
		$paycfg_1 = "content/savePayInfo"
		$paycfg_2 = "http://pay.fzw988.com/apiTvShow/itf/getallurlbyname?name=scanandzfb"
		$paycfg_3 = "pages/paySuccess.jsp"
		$paycfg_4 = "content/commquery"
		$paycfg_5 = "citicscan/wxscanUrl"
		$paycfg_6 = "citicscan/wxscanUrl3"
		$paycfg_7 = "ytwx/notify"
		$paycfg_8 = "ytwx/wapPay"
		$paycfg_9 = "qixun/wxH5Pay"
		$paycfg_10 = "citic/ali/scan"
		$paycfg_11 = "xiaoc/gwapPay"
		$paycfg_12 = "xyt/gwappay"
		$paycfg_13 = "zhongx/pay"
		$paycfg_14 = "13120747542/2818147339"
		$paycfg_15 = "http://pay.epgaclub.com/apiTvShow/"
		$paycfg_16 = "http://12.3.js.cn/tvr725.php"

	condition:
		any of them
		
		
}
