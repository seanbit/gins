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

type Encryption string

const (
	key_ctx_trace  = "/seanbit/gins/gateway/key_ctx_trace"
	EncryptionRsa  = Encryption("EncryptionRsa")
	EncryptionAes  = Encryption("EncryptionAes")
	EncryptionNone = Encryption("EncryptionNone")
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
	CorsAllowHeaders []string      `json:"cors_allow_headers"`
	SSL              *SSL
	RsaMap           map[string]*RSAKeyPair `json:"-" validate:"omitempty,dive,required"`
	ForwardedByClientIP bool
	SignalWatch      bool
	DefaultLang		 string
}

type SSL struct {
	CertFile string		`json:"cert_file" validate:"required,gte=1"`
	KeyFile  string		`json:"key_file" validate:"required,gte=1"`
}

type RSAKeyPair struct {
	ServerPubKey 		string 			`json:"server_pub_key" validate:"required"`
	ServerPriKey		string 			`json:"server_pri_key" validate:"required"`
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
	log = logger.WithField("LogIn", "gins")
	// config validate
	if err := validate.ValidateParameter(config); err != nil {
		log.Fatal(err)
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
	engine.ForwardedByClientIP = config.ForwardedByClientIP
	//engine.StaticFS(config.Upload.FileSavePath, http.Dir(GetUploadFilePath()))
	engine.Use(func(ctx *gin.Context) {
		var lang = ctx.GetHeader(HEADER_LANGUAGE)
		if  SupportLanguage(lang) == false {
			if len(_config.DefaultLang) > 0 {
				lang = _config.DefaultLang
			} else {
				lang = LanguageZh
			}
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
		clientIp := c.ClientIP()
		uri := c.Request.RequestURI
		apilog := log.WithFields(logrus.Fields{LogT:LogTypeRequestIn, "traceId":traceId, "path": path, "uri":uri, "method": method, "clientIp":clientIp})
		if len(c.Request.URL.RawQuery) > 0 {
			apilog.WithField("params", c.Request.URL.RawQuery)
		}
		apilog.Info("")
	})
	if config.CorsAllow {
		corscfg := cors.DefaultConfig()
		corscfg.AllowOrigins = []string{"*"}
		corscfg.AllowMethods = []string{"GET","POST","PUT","PATCH","DELETE","OPTIONS"}
		if config.CorsAllowHeaders != nil {
			corscfg.AllowHeaders = append(corscfg.AllowHeaders, config.CorsAllowHeaders...)
		}
		corscfg.AllowWebSockets = true
		if config.CorsAllowOrigins != nil {
			corscfg.AllowOrigins = config.CorsAllowOrigins
		}
		engine.Use(cors.New(corscfg))
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
		if config.SSL != nil {
			if err := s.ListenAndServeTLS(config.SSL.CertFile, config.SSL.KeyFile); err != nil {
				log.Fatal(fmt.Sprintf("Listen: %v\n", err))
			}
		} else {
			if err := s.ListenAndServe(); err != nil {
				log.Fatal(fmt.Sprintf("Listen: %v\n", err))
			}
		}
	}()
	if config.SignalWatch {
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
}

type Gin struct {
	Ctx *gin.Context
}

/**
 * 服务信息
 */
type Trace struct {
	Language  string     `json:"language"`
	EncMethod Encryption `json:"encMethod"`
	Params    []byte     `json:"params"`
	Key       []byte     `json:"key"`
	Rsa       *RSAConfig
	TraceId   uint64		`json:"traceId" validate:"required,gte=1"`
	UserId    uint64     `json:"userId" validate:"required,gte=1"`
	UserName  string     `json:"userName" validate:"required,gte=1"`
	UserRole  string		`json:"userRole" validate:"required,gte=1"`
	LogData   bool		`json:"logData"`
}

/**
 * 请求信息创建，并绑定至context上
 */
func NewTrace(ctx *gin.Context) *Trace {
	rq := &Trace{
		EncMethod: EncryptionNone,
		Params:    nil,
		Key:       nil,
		Rsa:       &RSAConfig{},
		LogData:   true,
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

	switch g.Trace().EncMethod {
	case EncryptionNone:
		if err := g.Ctx.Bind(parameter); err != nil {
			return foundation.NewError(err, STATUS_CODE_INVALID_PARAMS, err.Error())
		}
		g.LogRequestParam(parameter)
		return nil
	case EncryptionAes:fallthrough
	case EncryptionRsa:
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

	switch g.Trace().EncMethod {
	case EncryptionNone:
		g.LogResponseInfo(code, msg, data)
		g.Response(code, msg, data)
		return
	case EncryptionAes:
		jsonBytes, _ := json.Marshal(data)
		if secretBytes, err := encrypt.GetAes().EncryptCBC(jsonBytes, g.Trace().Key); err == nil {
			g.LogResponseInfo(code, msg, jsonBytes)
			g.Response(code, msg, base64.StdEncoding.EncodeToString(secretBytes))
			return
		}
		g.LogResponseInfo(code, msg, data)
		g.Response(code, msg, data)
		return
	case EncryptionRsa:
		jsonBytes, _ := json.Marshal(data)
		if g.Trace().Rsa.RespSign == true {
			if signBytes, err := encrypt.GetRsa().Sign(g.Trace().Rsa.ServerPriKey, jsonBytes); err == nil {
				log.Error(err)
			} else {
				g.Ctx.Writer.Header().Set(HEADER_REQUEST_SIGN, base64.StdEncoding.EncodeToString(signBytes))
			}
		}
		if g.Trace().Rsa.ClientPubKey == "" {
			g.LogResponseInfo(code, msg, data)
			g.Response(code, msg, data)
			return
		}
		if secretBytes, err := encrypt.GetRsa().Encrypt(g.Trace().Rsa.ClientPubKey, jsonBytes); err == nil {
			g.LogResponseInfo(code, msg, jsonBytes)
			g.Response(code, msg, base64.StdEncoding.EncodeToString(secretBytes))
			return
		}
		g.LogResponseInfo(code, msg, data)
		g.Response(code, msg, data)
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
		if msg == "" && ce.Msg() != "" {
			msg = ce.Msg()
		}
		g.LogResponseError(ce.Code(), msg, ce.Error())
		g.Response(ce.Code(), msg, nil)
		return
	}
	g.LogResponseError(STATUS_CODE_FAILED, err.Error(), "")
	g.Response(STATUS_CODE_FAILED, Msg(g.Trace().Language, STATUS_CODE_FAILED), nil)
}

/**
 * 响应数据
 */
func (g *Gin) Response(statusCode int, msg string, data interface{}) {
	g.Ctx.JSON(http.StatusOK, gin.H{
		"code" : statusCode,
		"msg" :  msg,
		"data" : data,
	})
	return
}


