package gins

import (
	"encoding/base64"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"github.com/seanbit/gokit/encrypt"
	"github.com/seanbit/gokit/foundation"
	"github.com/seanbit/gokit/validate"
)

const (
	HEADER_TOKEN_AUTH   = "Authorization"
	HEADER_API_VERSION  = "api-version"
	HEADER_REQUEST_SIGN = "sign"
)

type SecretParams struct {
	Data string	`json:"data" validate:"required,base64"`
}

type RSAConfig struct {
	ReqSign				bool
	RespSign			bool
	ServerPubKey 		string 			`json:"server_pub_key" validate:"required"`
	ServerPriKey		string 			`json:"server_pri_key" validate:"required"`
	ClientPubKey 		string 			`json:"client_pub_key"`
}

type TokenParseFunc func(ctx *gin.Context, token string) (userId uint64, userName, role, key string, err error)

type CPKGetFunc func(ctx *gin.Context) (cpk string, err error)

/**
 * rsa拦截校验
 */
func InterceptRsa(reqSign, respSign bool, cpkGet CPKGetFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		g := Gin{ctx}
		// get rsa config
		clientVersion := ctx.GetHeader(HEADER_API_VERSION)
		keyPair, ok := _config.RsaMap[clientVersion]
		if !ok {
			g.ResponseError(foundation.NewError(nil, STATUS_CODE_RSA_VERSION_FIT_FAILED, ""))
			ctx.Abort()
			return
		}
		if err := validate.ValidateParameter(keyPair); err != nil {
			log.Fatal(err)
		}
		g.Trace().Rsa.ReqSign = reqSign
		g.Trace().Rsa.RespSign = respSign
		g.Trace().Rsa.ServerPubKey = keyPair.ServerPubKey
		g.Trace().Rsa.ServerPriKey = keyPair.ServerPriKey

		// params
		var code = STATUS_CODE_SUCCESS
		var params SecretParams
		var encrypted []byte
		var jsonBytes []byte

		// decrypt
		if err := g.Ctx.Bind(&params); err != nil { // bind
			code = STATUS_CODE_INVALID_PARAMS
		} else if err := validate.ValidateParameter(params); err != nil { // validate
			code = STATUS_CODE_INVALID_PARAMS
		} else if encrypted, err = base64.StdEncoding.DecodeString(params.Data); err != nil { // decode
			code = STATUS_CODE_SECRET_CHECK_FAILED
		} else if jsonBytes, err = encrypt.GetRsa().Decrypt(g.Trace().Rsa.ServerPriKey, encrypted); err != nil { // decrypt
			code = STATUS_CODE_SECRET_CHECK_FAILED
		}

		// sign verify
		if code == STATUS_CODE_SUCCESS && g.Trace().Rsa.ReqSign {
			if cpk, err  := cpkGet(ctx); err != nil {
				code = STATUS_CODE_CLIENT_PUBKEY_EMPTY
			} else if sign := ctx.GetHeader(HEADER_REQUEST_SIGN); sign == "" {
				code = STATUS_CODE_SIGN_IS_EMPTY
			} else if signDatas, err := base64.StdEncoding.DecodeString(sign); err != nil {
				code = STATUS_CODE_SIGN_VALIDATE_FAILED
			} else if err = encrypt.GetRsa().Verify(cpk, jsonBytes, signDatas); err != nil { // sign verify
				code = STATUS_CODE_SECRET_CHECK_FAILED
			} else {
				g.Trace().Rsa.ClientPubKey = cpk
			}
		}

		// code check
		if code != STATUS_CODE_SUCCESS {
			g.ResponseError(foundation.NewError(nil, code, ""))
			ctx.Abort()
			return
		}
		// ctx
		g.Trace().EncMethod = EncryptionRsa
		g.Trace().Params = jsonBytes
		// next
		ctx.Next()
	}
}

/**
 * token拦截校验
 */
func InterceptToken(tokenParse TokenParseFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		g := Gin{ctx}
		if userId, userName, role, key, err := tokenParse(ctx, ctx.GetHeader(HEADER_TOKEN_AUTH)); err != nil {
			g.ResponseError(err)
			ctx.Abort()
			return
		} else {
			g.Trace().UserId = userId
			g.Trace().UserName = userName
			g.Trace().UserRole = role
			g.Trace().Key, _ = hex.DecodeString(key)
			// next
			ctx.Next()
		}
	}
}

/**
 * aes拦截校验
 */
func InterceptAes() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		g := Gin{ctx}
		var code = STATUS_CODE_SUCCESS
		var params SecretParams
		var encrypted []byte
		var jsonBytes []byte

		// params handle
		if err := g.Ctx.Bind(&params); err != nil { // bind
			code = STATUS_CODE_SECRET_CHECK_FAILED
		} else if err := validate.ValidateParameter(params); err != nil { // validate
			code = STATUS_CODE_INVALID_PARAMS
		} else if encrypted, err = base64.StdEncoding.DecodeString(params.Data); err != nil { // decode
			code = STATUS_CODE_SECRET_CHECK_FAILED
		} else if jsonBytes, err = encrypt.GetAes().DecryptCBC(encrypted, g.Trace().Key); err != nil { // decrypt
			code = STATUS_CODE_SECRET_CHECK_FAILED
		}
		// code check
		if code != STATUS_CODE_SUCCESS {
			g.ResponseError(foundation.NewError(nil, code, ""))
			ctx.Abort()
			return
		}

		g.Trace().EncMethod = EncryptionAes
		g.Trace().Params = jsonBytes
		// next
		ctx.Next()
	}
}
