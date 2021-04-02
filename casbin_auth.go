package casbin

import (
	"github.com/suisrc/config.zgo"
	"github.com/suisrc/res.zgo"
)

// 角色定义：
// 1.用户在租户和租户应用上有且各自具有一个角色
// 2.如果在同一个位置(租户或应用)上有多个角色， 服务直接拒绝
// 3.子应用角色优先于租户角色(名称排他除外)
// 3.子应用可以使用使用X-Request-Svc-[SVC-NAME]-Role指定服务角色， 且角色有限被使用

// UseAuthCasbinMiddleware 用户授权中间件
func (a *Auther) UseAuthCasbinMiddleware(skippers ...res.SkipperFunc) res.HandlerFunc {
	return a.UseAuthCasbinMiddlewareByOrigin(func(c res.ReqContext, k string) (string, error) { return "default", nil }, skippers...)
}

// UseAuthCasbinMiddlewareByOrigin 用户授权中间件
func (a *Auther) UseAuthCasbinMiddlewareByOrigin(xget func(res.ReqContext, string) (string, error), skippers ...res.SkipperFunc) res.HandlerFunc {
	if !config.C.JWTAuth.Enable {
		return res.EmptyMiddleware()
	}
	conf := config.C.Casbin
	return func(c res.ReqContext) {
		if res.SkipHandler(c, skippers...) {
			c.Next() // 需要跳过权限验证的uri内容
			return
		}
		a.AuthCasbinMiddlewareByOrigin(c, conf, xget)
	}
}
