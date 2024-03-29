package gins

import (
	"encoding/json"
	"github.com/seanbit/gokit/foundation"
	"github.com/sirupsen/logrus"
)

type LogType string

const (
	LogT				= "GIN"
	LogTypeRequestIn 	= LogType("ReqIn")
	LogTypeRequestInfo 	= LogType("ReqInfo")
	LogTypeResponseTo 	= LogType("RespTo")
	LogTypeResponseErr 	= LogType("RespErr")
)

func (g *Gin) LogRequestParam(parameter interface{}) {
	traceId := g.Trace().TraceId
	userId := g.Trace().UserId
	userName := g.Trace().UserName
	role := g.Trace().UserRole
	apilog := log.WithFields(logrus.Fields{LogT:LogTypeRequestInfo, "traceId":traceId, "userId":userId, "userName":userName, "role":role})
	if jsonBytes, ok := parameter.([]byte); ok {
		apilog.Info(string(jsonBytes))
	} else if jsonBytes, err := json.Marshal(parameter); err == nil {
		apilog.Info(string(jsonBytes))
	} else {
		apilog.Info(parameter)
	}
}

func (g *Gin) LogResponseInfo(code int, msg string, data interface{}) {
	traceId := g.Trace().TraceId
	userId := g.Trace().UserId
	userName := g.Trace().UserName
	role := g.Trace().UserRole
	apilog := log.WithFields(logrus.Fields{LogT:LogTypeResponseTo, "traceId":traceId, "userId":userId, "userName":userName, "role":role, "code":code, "msg":msg})

	if _config.RunMode != foundation.RUN_MODE_DEBUG && g.Trace().LogData == false {
		apilog.Info("")
		return
	}
	if jsonBytes, ok := data.([]byte); ok {
		apilog.Info(string(jsonBytes))
	} else if jsonBytes, err := json.Marshal(data); err == nil {
		apilog.Info(string(jsonBytes))
	} else {
		apilog.Info(data)
	}
}

func (g *Gin) LogResponseError(code int, msg string, err string) {
	traceId := g.Trace().TraceId
	userId := g.Trace().UserId
	userName := g.Trace().UserName
	role := g.Trace().UserRole
	apilog := log.WithFields(logrus.Fields{LogT:LogTypeResponseErr, "traceId":traceId, "userId":userId, "userName":userName, "role":role, "code":code, "msg":msg})
	apilog.Info(err)
}

//engine.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
//	// 你的自定义格式
//	if param.ErrorMessage == "" {
//		return fmt.Sprintf("[GIN]%s requestid:%d clientip:%s method:%s path:%s code:%d\n",
//			param.TimeStamp.Format("2006/01/02 15:04:05"),
//			param.Keys[key_trace_id].(uint64),
//			param.ClientIP,
//			param.Method,
//			param.Path,
//			param.StatusCode,
//		)
//	}
//	return fmt.Sprintf("[GIN]%s requestid:%d clientip:%s method:%s path:%s code:%d errmsg:%s\n",
//		param.TimeStamp.Format("2006/01/02 15:04:05"),
//		param.Keys[key_trace_id].(uint64),
//		param.ClientIP,
//		param.Method,
//		param.Path,
//		param.StatusCode,
//		param.ErrorMessage,
//		)
//}))