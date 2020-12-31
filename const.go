package gins


const (
	HEADER_LANGUAGE   = "Accept-Language"
	LanguageZh string = "zh_CN"
	LanguageEn string = "en_US"
)

type codeMsg struct {
	language string
	codeMap  map[string]map[int]string
}

var _codemsg = &codeMsg{
	codeMap: make(map[string]map[int]string),
}

func init() {
	en := make(map[int]string)
	_codemsg.codeMap[LanguageEn] = en
	cn := make(map[int]string)
	_codemsg.codeMap[LanguageZh] = cn
}

func AddMsgLanguage(lang string)  {
	_codemsg.codeMap[lang] = make(map[int]string)
}

func SupportLanguage(lang string) bool {
	if _, ok := _codemsg.codeMap[lang]; ok == true {
		return true
	}
	return false
}

func SetMsgMap(lang string, msgMap map[int]string) {
	if codemsg, ok := _codemsg.codeMap[lang]; ok {
		for k, v := range msgMap {
			codemsg[k] = v
		}
	} else {
		_codemsg.codeMap[lang] = msgMap
	}
}

func SetMsg(lang string, code int, msg string) {
	if codemsg, ok := _codemsg.codeMap[lang]; ok {
		codemsg[code] = msg
	} else {
		AddMsgLanguage(lang)
		_codemsg.codeMap[lang][code] = msg
	}
}

func Msg(lang string, code int) string {
	if codemsg, ok := _codemsg.codeMap[lang]; ok {
		if msg, ok := codemsg[code]; ok {
			return msg
		}
	}
	return ""
}

const (
	// base
	STATUS_CODE_SUCCESS        					= 200
	STATUS_CODE_INVALID_PARAMS 					= 400
	STATUS_CODE_ERROR          					= 500
	STATUS_CODE_FAILED         					= 800

	// secret
	STATUS_CODE_RSA_VERSION_FIT_FAILED			= 840
	STATUS_CODE_SIGN_IS_EMPTY					= 841
	STATUS_CODE_SIGN_VALIDATE_FAILED			= 842
	STATUS_CODE_SECRET_CHECK_FAILED    			= 843
	STATUS_CODE_PERMISSION_DENIED    			= 844
	STATUS_CODE_CLIENT_PUBKEY_EMPTY    			= 845

	// upload
	STATUS_CODE_UPLOAD_FILE_SAVE_FAILED        	= 811
	STATUS_CODE_UPLOAD_FILE_CHECK_FAILED       	= 812
	STATUS_CODE_UPLOAD_FILE_CHECK_FORMAT_WRONG 	= 813
)

func init() {
	SetMsgMap(LanguageZh, map[int]string{
		STATUS_CODE_SUCCESS : 						"操作成功",
		STATUS_CODE_INVALID_PARAMS : 				"参数校验失败",
		STATUS_CODE_ERROR : 						"系统繁忙",
		STATUS_CODE_FAILED : 						"操作失败",
		STATUS_CODE_RSA_VERSION_FIT_FAILED : 		"安全证书版本匹配失败",
		STATUS_CODE_SIGN_IS_EMPTY :					"请求签名为空",
		STATUS_CODE_SIGN_VALIDATE_FAILED :			"请求签名校验失败",
		STATUS_CODE_SECRET_CHECK_FAILED : 			"安全校验失败",
		STATUS_CODE_PERMISSION_DENIED : 			"您没有访问权限",
		STATUS_CODE_UPLOAD_FILE_SAVE_FAILED : 		"文件保存失败",
		STATUS_CODE_UPLOAD_FILE_CHECK_FAILED : 		"文件校验失败",
		STATUS_CODE_UPLOAD_FILE_CHECK_FORMAT_WRONG :"文件校验错误，文件格式或大小不正确",
	})
	SetMsgMap(LanguageEn, map[int]string{
		STATUS_CODE_SUCCESS : 						"ok",
		STATUS_CODE_INVALID_PARAMS : 				"params validate failed",
		STATUS_CODE_ERROR : 						"system busy",
		STATUS_CODE_FAILED : 						"failed",
		STATUS_CODE_RSA_VERSION_FIT_FAILED : 		"safe cert version fit failed",
		STATUS_CODE_SIGN_IS_EMPTY :					"request sign empty",
		STATUS_CODE_SIGN_VALIDATE_FAILED :			"request sign validate failed",
		STATUS_CODE_SECRET_CHECK_FAILED : 			"secret check failed",
		STATUS_CODE_PERMISSION_DENIED : 			"permission denied",
		STATUS_CODE_UPLOAD_FILE_SAVE_FAILED : 		"file save failed",
		STATUS_CODE_UPLOAD_FILE_CHECK_FAILED : 		"file check failed",
		STATUS_CODE_UPLOAD_FILE_CHECK_FORMAT_WRONG :"file format or size wrong",
	})
}






