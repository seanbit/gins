package gins

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
)

func (g *Gin) LogRequestParam(parameter interface{}) {
	traceId := g.Trace().TraceId
	userId := g.Trace().UserId
	userName := g.Trace().UserName
	role := g.Trace().UserRole
	apilog := log.WithFields(logrus.Fields{"traceId":traceId, "userId":userId, "userName":userName, "role":role})
	if jsonBytes, ok := parameter.([]byte); ok {
		apilog.WithField("params", string(jsonBytes)).Info("request in")
	} else if jsonBytes, err := json.Marshal(parameter); err == nil {
		apilog.WithField("params", string(jsonBytes)).Info("request in")
	} else {
		apilog.WithField("params", parameter).Info("request in")
	}
}

func (g *Gin) LogResponseInfo(code int, msg string, data interface{}, sign string) {
	traceId := g.Trace().TraceId
	userId := g.Trace().UserId
	userName := g.Trace().UserName
	role := g.Trace().UserRole
	apilog := log.WithFields(logrus.Fields{"traceId":traceId, "userId":userId, "userName":userName, "role":role, "respcode":code, "respmsg":msg, "sign":sign})

	if jsonBytes, ok := data.([]byte); ok {
		apilog.WithField("respdata", string(jsonBytes)).Info("response to")
	} else if jsonBytes, err := json.Marshal(data); err == nil {
		apilog.WithField("respdata", string(jsonBytes)).Info("response to")
	} else {
		apilog.WithField("respdata", data).Info("response to")
	}
}

func (g *Gin) LogResponseError(code int, msg string, err string) {
	traceId := g.Trace().TraceId
	userId := g.Trace().UserId
	userName := g.Trace().UserName
	role := g.Trace().UserRole
	apilog := log.WithFields(logrus.Fields{"traceId":traceId, "userId":userId, "userName":userName, "role":role, "respcode":code, "respmsg":msg})
	apilog.Info(err)
	if err != "" {
		apilog.Error(err)
	}
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