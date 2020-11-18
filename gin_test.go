package gins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/seanbit/gokit/foundation"
	"github.com/seanbit/gokit/validate"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

type User struct {
	UserId int						`json:"user_id" validate:"required,min=1"`
	UserName string					`json:"user_name" validate:"required,eorp"`
	Email string					`json:"email" validate:"required,email"`
}

type GoodsPayInfoParameter struct {
	GoodsId int			`json:"goods_id" validate:"required,min=1"`
	GoodsName string	`json:"goods_name" validate:"required,gte=1"`
	GoodsAmount int		`json:"goods_amount" validate:"required,min=1"`
	Remark string 		`json:"remark" validate:"gte=0"`
}

type GoodsPayParameter struct {
	UserInfo *User					`json:"user_info" validate:"required"`
	Goods []*GoodsPayInfoParameter	`json:"goods" validate:"required,gte=1,dive,required"`
	GoodsIds []int				`json:"goods_ids" validate:"required,gte=1,dive,min=1"`
}

func TestGinServer(t *testing.T) {
	// server start
	Serve(HttpConfig{
		RunMode:          "test",
		WorkerId:         0,
		HttpPort:         8001,
		ReadTimeout:      60 * time.Second,
		WriteTimeout:     60 * time.Second,
	}, nil, RegisterApi)
}

func RegisterApi(engine *gin.Engine) {
	apiv1 := engine.Group("api/order/v1")
	{
		apiv1.POST("/bindtest", bindtest)
	}
	engine.Static("/Desktop", "/Users/Sean/Desktop")
}
/*
	StaticFile(string, string) IRoutes	静态文件路由 router.StaticFile("favicon.ico", "./resources/favicon.ico")
	Static(string, string) IRoutes	静态文件夹路由 router.Static("/路由","./文件夹目录")
	StaticFS(string, http.FileSystem) IRoutes	静态文件路由 router.Static("/路由",gin.Dir("FileSystem"))
 */

func bindtest(ctx *gin.Context)  {
	date := ctx.Request.Header.Get("Date")
	fmt.Println(date)
	g := Gin{
		Ctx: ctx,
	}
	var parameter GoodsPayParameter
	if err := g.BindParameter(&parameter); err != nil {
		g.ResponseError(err)
		return
	}
	var payMoney float64 = 0
	if err := GoodsPay(ctx, &parameter, &payMoney); err != nil {
		g.ResponseError(err)
		return
	}
	var resp = make(map[string]string)
	resp["payMoney"] = fmt.Sprintf("%v", payMoney)
	g.ResponseData(resp)
}

func GoodsPay(ctx context.Context, parameter *GoodsPayParameter, payMoney *float64) error {
	err := validate.ValidateParameter(parameter)
	if err != nil {
		return foundation.NewError(err, STATUS_CODE_INVALID_PARAMS, err.Error())
	}
	*payMoney = 10.0
	return nil
}

func TestPostToGinServer(t *testing.T)  {
	var url = "http://localhost:8001/api/order/v1/bindtest"

	var user_info map[string]interface{} = make(map[string]interface{})
	user_info["user_id"] = 101
	user_info["user_name"] = "18922311056"
	user_info["email"] = "1028990481@qq.com"

	var goods1 map[string]interface{} = make(map[string]interface{})
	goods1["goods_id"] = 1001
	goods1["goods_name"] = "三只松鼠干果巧克力100g包邮"
	goods1["goods_amount"] = 1
	goods1["remark"] = ""
	var goods []interface{} = []interface{}{goods1}
	var goods_ids []int = []int{1}

	var parameter map[string]interface{} = make(map[string]interface{})
	parameter["user_info"] = user_info
	parameter["goods"] = goods
	parameter["goods_ids"] = goods_ids

	jsonStr, err := json.Marshal(parameter)
	if err != nil {
		fmt.Printf("to json error:%v\n", err)
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "en_US")

	client := &http.Client{}
	resp, err := client.Do(req)
	//defer resp.Body.Close()
	if err != nil {
		fmt.Printf("resp error:%v", err)
	} else {
		statuscode := resp.StatusCode
		hea := resp.Header
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println(string(body))
		fmt.Println(statuscode)
		fmt.Println(hea)
	}
}

func TestRequestion(t *testing.T) {
	fmt.Println("success")
	//ctx := &gin.Context{}
	//g := Gin{ctx}
	//newTrace(ctx)
	//g.Trace().Language = requisition.LanguageZh
	//fmt.Println(g.Trace().Language)
	//var err error = requisition.NewError(nil,STATUS_CODE_PERMISSION_DENIED)
	//if e, ok := err.(requisition.IError); ok {
	//	e.SetLang(g.Trace().Language)
	//}
	//if e, ok := err.(foundation.IError); ok {
	//	fmt.Println(e.Code(), e.Msg(), e.Error())
	//}
}