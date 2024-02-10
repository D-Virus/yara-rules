rule MAL_SnakeLogger {
	meta: 
		author = "dvirus" 
		description = "Detect SnakeKeylogger"
		sha256 = "8af7f091c0c869006be53ef947b10ee18ddf6a2c2870a9b163484a372f94b90a"
       		reference = "https://bazaar.abuse.ch/sample/8af7f091c0c869006be53ef947b10ee18ddf6a2c2870a9b163484a372f94b90a/"
	strings:
        	$s1 = "Private Declare Function tAcKs Lib"
        	$s2 = "l Gmrjz As Long, ByValt As Long) As Long"
        	$s3 = "VN.inf,DEfaULTINSTALL_singleusER,1"
        	$s4 = "_	_	_	?"
        	$s5 = "ADVpacK.DLl"
        	$s6 = "DOCumeNt_OPEn"
        	$s7 = "aUtOopEn"

	condition:
        	4 of ($s*)
}
