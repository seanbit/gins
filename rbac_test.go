package gins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/storyicon/grbac"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

func TestGinRbacServer(t *testing.T) {
	// server start
	Serve(HttpConfig{
		RunMode:          "test",
		WorkerId:         0,
		HttpPort:         8001,
		ReadTimeout:      60 * time.Second,
		WriteTimeout:     60 * time.Second,
	}, nil, rbac_RegisterApi)
}

func rbac_RegisterApi(engine *gin.Engine) {
	apiv1 := engine.Group("api/order/v1")
	{
	}
	apiv1.Use(testauthorization(LoadAuthorizationRules))
	{
		apiv1.POST("/rbactest", rbactest)
		apiv1.POST("/user/:userId", userget)
	}
}

func rbactest(ctx *gin.Context)  {
	date := ctx.Request.Header.Get("Date")
	fmt.Println(date)
	g := Gin{
		Ctx: ctx,
	}
	g.ResponseData("asdzcbjubbnzcbzxc")
}

func userget(ctx *gin.Context)  {
	date := ctx.Request.Header.Get("Date")
	fmt.Println(date)
	g := Gin{
		Ctx: ctx,
	}
	g.ResponseData(ctx.Params.ByName("userId"))
}

func testauthorization(rulesLoader  func()(grbac.Rules, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		rbac, err := grbac.New(grbac.WithLoader(rulesLoader, time.Minute))
		if err != nil {
			_ = c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		roles := []string{c.GetHeader("role")}
		state, _ := rbac.IsRequestGranted(c.Request, roles)
		if !state.IsGranted() {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func LoadAuthorizationRules() (rules grbac.Rules, err error) {

	// 在这里实现你的逻辑
	// ...
	// 你可以从数据库或文件加载授权规则
	// 但是你需要以 grbac.Rules 的格式返回你的身份验证规则
	// 提示：你还可以将此函数绑定到golang结构体
	rules = []*grbac.Rule{
		&grbac.Rule{ID:1001, Resource:&grbac.Resource{Host:"localhost:8001", Path:"/api/order/v1/rbactest", Method:"POST"}, Permission: &grbac.Permission{AuthorizedRoles: []string{"superadmin"}, AllowAnyone:false}},
		&grbac.Rule{ID:101, Resource:&grbac.Resource{Host:"localhost:8001", Path:"**/10023", Method:"POST"}, Permission: &grbac.Permission{AuthorizedRoles: []string{"useradmin"}, AllowAnyone:false}},
	}
	err = nil
	return
}


func TestPostWithRbac(t *testing.T) {
	var url = "http://localhost:8001/api/order/v1/rbactest"
	var parameter map[string]interface{} = make(map[string]interface{})
	parameter["username"] = "sean"
	jsonStr, err := json.Marshal(parameter)
	if err != nil {
		fmt.Printf("to json error:%v\n", err)
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("role", "superadmin")
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

func TestPostWithRbacUserGet(t *testing.T) {
	var url = "http://localhost:8001/api/order/v1/user/10023"
	var parameter map[string]interface{} = make(map[string]interface{})
	parameter["username"] = "sean"
	jsonStr, err := json.Marshal(parameter)
	if err != nil {
		fmt.Printf("to json error:%v\n", err)
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("role", "useradmin")
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