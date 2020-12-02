package gins

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/seanbit/gokit/encrypt"
	"github.com/seanbit/gokit/foundation"
	"github.com/seanbit/gokit/validate"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"time"
)

type secret_method string
const (
	key_ctx_trace                     = "/seanbit/goweb/gateway/key_ctx_trace"
	_                   secret_method = ""
	secret_method_rsa   secret_method = "secret_method_rsa"
	secret_method_aes   secret_method = "secret_method_aes"
	secret_method_nouse secret_method = "secret_method_nouse"
)

type CError interface {
	Code() int
	Msg() string
}

type HttpConfig struct {
	RunMode          string        `json:"-" validate:"required,oneof=debug test release"`
	WorkerId         int64         `json:"-" validate:"min=0"`
	HttpPort         int           `json:"-"`
	ReadTimeout      time.Duration `json:"read_timeout" validate:"required,gte=1"`
	WriteTimeout     time.Duration `json:"write_timeout" validate:"required,gte=1"`
	CorsAllow        bool          `json:"cors_allow"`
	CorsAllowOrigins []string      `json:"cors_allow_origins"`
	RsaOpen          bool          `json:"rsa_open"`
	RsaMap           map[string]*RsaConfig    `json:"-"`
}

/** 服务注册回调函数 **/
type GinRegisterFunc func(engine *gin.Engine)

var (
	_config   	HttpConfig
	_idWorker 	foundation.SnowId
	log *logrus.Entry
)

/**
 * 启动 api server
 * handler: 接口实现serveHttp的对象
 */
func Serve(config HttpConfig, logger logrus.FieldLogger, registerFunc GinRegisterFunc) {
	if logger == nil {
		logger = logrus.New()
	}
	log = logger.WithField("stage", "ginserver")
	// config validate
	if err := validate.ValidateParameter(config); err != nil {
		log.Fatal(err)
	}
	if config.RsaOpen {
		if config.RsaMap == nil {
			log.Fatal("server http start error : secret is nil")
		}
		if err := validate.ValidateParameter(config.RsaMap); err != nil {
			log.Fatal(err)
		}
	}
	_config = config
	_idWorker, _ = foundation.NewWorker(config.WorkerId)

	// gin
	gin.SetMode(config.RunMode)
	gin.DisableConsoleColor()
	//gin.DefaultWriter = io.MultiWriter(log.Logger.Writer(), os.Stdout)

	// engine
	//engine := gin.Default()
	engine := gin.New()
	engine.Use(gin.Recovery())
	//engine.StaticFS(config.Upload.FileSavePath, http.Dir(GetUploadFilePath()))
	engine.Use(func(ctx *gin.Context) {
		var lang = ctx.GetHeader(HEADER_LANGUAGE)
		if  SupportLanguage(lang) == false {
			lang = LanguageZh
		}
		trace := NewTrace(ctx)
		trace.Language = lang
		trace.TraceId = uint64(_idWorker.GetId())
		ctx.Set(key_ctx_trace, trace)
		ctx.Next()
	})

	engine.Use(func(c *gin.Context) {
		g := Gin{c}
		path := c.Request.URL.Path
		method := c.Request.Method
		traceId := g.Trace().TraceId
		clientIp := c.Request.RemoteAddr
		uri := c.Request.RequestURI
		apilog := log.WithFields(logrus.Fields{LogT:LogTypeRequestIn, "traceId":traceId, "path": path, "uri":uri, "method": method, "clientIp":clientIp})
		if len(c.Request.URL.RawQuery) > 0 {
			apilog.WithField("params", c.Request.URL.RawQuery)
		}
		apilog.Info("")
	})
	if config.CorsAllow {
		if config.CorsAllowOrigins != nil {
			corscfg := cors.DefaultConfig()
			corscfg.AllowOrigins = config.CorsAllowOrigins
			engine.Use(cors.New(corscfg))
		} else {
			engine.Use(cors.Default())
		}

	}
	registerFunc(engine)
	// server
	s := http.Server{
		Addr:           fmt.Sprintf(":%d", config.HttpPort),
		Handler:        engine,
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Fatal(fmt.Sprintf("Listen: %v\n", err))
		}
	}()
	// signal
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<- quit
	log.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	log.Println("Server exiting")
}

type Gin struct {
	Ctx *gin.Context
}

/**
 * 服务信息
 */
type Trace struct {
	Language 	 string
	SecretMethod secret_method `json:"secretMethod"`
	Params       []byte        `json:"params"`
	Key          []byte        `json:"key"`
	Rsa			 *RsaConfig
	TraceId 	uint64		`json:"traceId" validate:"required,gte=1"`
	UserId      uint64      `json:"userId" validate:"required,gte=1"`
	UserName    string      `json:"userName" validate:"required,gte=1"`
	UserRole	string		`json:"userRole" validate:"required,gte=1"`
}

/**
 * 请求信息创建，并绑定至context上
 */
func NewTrace(ctx *gin.Context) *Trace {
	rq := &Trace{
		SecretMethod: secret_method_nouse,
		Params:       nil,
		Key:          nil,
		Rsa: 		  nil,
	}
	ctx.Set(key_ctx_trace, rq)
	return rq
}

/**
 * 信息获取，获取传输链上context绑定的用户请求调用信息
 */
func (g *Gin) Trace() *Trace {
	obj := g.Ctx.Value(key_ctx_trace)
	if info, ok := obj.(*Trace); ok {
		return  info
	}
	return nil
}

/**
 * 参数绑定
 */
func (g *Gin) BindParameter(parameter interface{}) error {

	switch g.Trace().SecretMethod {
	case secret_method_nouse:
		if err := g.Ctx.Bind(parameter); err != nil {
			return foundation.NewError(err, STATUS_CODE_INVALID_PARAMS, err.Error())
		}
		g.LogRequestParam(parameter)
		return nil
	case secret_method_aes:fallthrough
	case secret_method_rsa:
		if err := json.Unmarshal(g.Trace().Params, parameter); err != nil {
			return foundation.NewError(err, STATUS_CODE_INVALID_PARAMS, err.Error())
		}
		g.LogRequestParam(parameter)
		return nil
	}
	return nil
}

/**
 * 响应数据，成功，原数据转json返回
 */
func (g *Gin) ResponseData(data interface{}) {
	var code = STATUS_CODE_SUCCESS
	var msg = Msg(g.Trace().Language, code)

	switch g.Trace().SecretMethod {
	case secret_method_nouse:
		g.LogResponseInfo(code, msg, data, "")
		g.Response(code, msg, data, "")
		return
	case secret_method_aes:
		jsonBytes, _ := json.Marshal(data)
		if secretBytes, err := encrypt.GetAes().EncryptCBC(jsonBytes, g.Trace().Key); err == nil {
			g.LogResponseInfo(code, msg, jsonBytes, "")
			g.Response(code, msg, base64.StdEncoding.EncodeToString(secretBytes), "")
			return
		}
		g.LogResponseInfo(code, msg, data, "response data aes encrypt failed")
		g.Response(code, msg, data, "response data aes encrypt failed")
		return
	case secret_method_rsa:
		jsonBytes, _ := json.Marshal(data)
		if secretBytes, err := encrypt.GetRsa().Encrypt(g.Trace().Rsa.ClientPubKey, jsonBytes); err == nil {
			if signBytes, err := encrypt.GetRsa().Sign(g.Trace().Rsa.ServerPriKey, jsonBytes); err == nil {
				sign := base64.StdEncoding.EncodeToString(signBytes)
				g.LogResponseInfo(code, msg, jsonBytes, sign)
				g.Response(code, msg, base64.StdEncoding.EncodeToString(secretBytes), sign)
				return
			}
		}
		g.LogResponseInfo(code, msg, data, "response data rsa encrypt failed")
		g.Response(code, msg, data, "response data rsa encrypt failed")
		return
	}
}

/**
 * 响应数据，自定义error
 */
func (g *Gin) ResponseError(err error) {
	var ce foundation.Error = nil
	if e, ok := err.(foundation.Error); ok {
		ce = e
	} else if e, ok := foundation.ParseError(err); ok {
		ce = e
	}
	if ce != nil {
		msg := Msg(g.Trace().Language, ce.Code())
		g.LogResponseError(ce.Code(), msg, ce.Error())
		g.Response(ce.Code(), msg, nil, "")
		return
	}
	g.LogResponseError(STATUS_CODE_FAILED, err.Error(), "")
	g.Response(STATUS_CODE_FAILED, err.Error(), nil, "")
}

/**
 * 响应数据
 */
func (g *Gin) Response(statusCode int, msg string, data interface{}, sign string) {
	g.Ctx.JSON(http.StatusOK, gin.H{
		"code" : statusCode,
		"msg" :  msg,
		"data" : data,
		"sign" : sign,
	})
	return
}

