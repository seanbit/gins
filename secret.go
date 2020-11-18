package gins

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"github.com/seanbit/gokit/encrypt"
	"github.com/seanbit/gokit/foundation"
	"github.com/seanbit/gokit/validate"
)

const (
	HEADER_TOKEN_AUTH = "Authorization"
	HEADER_CLIENT_VERSION = "Version"
	HEADER_CLIENT_SIGN = "sign"
)

type SecretParams struct {
	Secret string	`json:"secret" validate:"required,base64"`
}

type RsaConfig struct {
	ServerPubKey 		string 			`json:"server_pub_key" validate:"required"`
	ServerPriKey		string 			`json:"server_pri_key" validate:"required"`
	ClientPubKey 		string 			`json:"client_pub_key" validate:"required"`
}

type TokenParseFunc func(ctx context.Context, token string) (userId uint64, userName, role, key string, err error)

/**
 * rsa拦截校验
 */
func InterceptRsa() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		g := Gin{ctx}
		clientVersion := ctx.GetHeader(HEADER_CLIENT_VERSION)
		rsa, ok := _config.RsaMap[clientVersion]
		if !ok {
			g.ResponseError(foundation.NewError(nil, STATUS_CODE_RSA_VERSION_FIT_FAILED, ""))
			ctx.Abort()
			return
		}
		if err := validate.ValidateParameter(rsa); err != nil {
			log.Fatal(err)
		}
		g.Trace().Rsa = rsa

		var code = STATUS_CODE_SUCCESS
		var params SecretParams
		var encrypted []byte
		var jsonBytes []byte
		if sign := ctx.GetHeader(HEADER_CLIENT_SIGN); sign == "" {
			code = STATUS_CODE_SIGN_IS_EMPTY
		} else if signDatas, err := base64.StdEncoding.DecodeString(sign); err != nil {
			code = STATUS_CODE_SIGN_VALIDATE_FAILED
		} else if err := g.Ctx.Bind(&params); err != nil { // bind
			code = STATUS_CODE_SECRET_CHECK_FAILED
		} else if err := validate.ValidateParameter(params); err != nil { // validate
			code = STATUS_CODE_INVALID_PARAMS
		} else if encrypted, err = base64.StdEncoding.DecodeString(params.Secret); err != nil { // decode
			code = STATUS_CODE_SECRET_CHECK_FAILED
		} else if jsonBytes, err = encrypt.GetRsa().Decrypt(rsa.ServerPriKey, encrypted); err != nil { // decrypt
			code = STATUS_CODE_SECRET_CHECK_FAILED
		} else if err = encrypt.GetRsa().Verify(rsa.ClientPubKey, jsonBytes, signDatas); err != nil { // sign verify
			code = STATUS_CODE_SECRET_CHECK_FAILED
		}
		// code check
		if code != STATUS_CODE_SUCCESS {
			g.ResponseError(foundation.NewError(nil, code, ""))
			ctx.Abort()
			return
		}
		g.Trace().SecretMethod = secret_method_rsa
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
		} else if encrypted, err = base64.StdEncoding.DecodeString(params.Secret); err != nil { // decode
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

		g.Trace().SecretMethod = secret_method_aes
		g.Trace().Params = jsonBytes
		// next
		ctx.Next()
	}
}
