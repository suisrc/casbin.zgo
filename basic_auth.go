package casbin

import (
	"github.com/suisrc/auth.zgo"
	"github.com/suisrc/res.zgo"
)

// UseAuthBasicMiddleware 用户授权中间件, 只判定登录权限
func (a *Auther) UseAuthBasicMiddleware(skippers ...res.SkipperFunc) res.HandlerFunc {
	return func(c res.Context) {
		if res.SkipHandler(c, skippers...) {
			c.Next()
			return
		}

		user, err := a.Implor.GetAuther().GetUserInfo(c, "")
		if err != nil {
			if err == auth.ErrNoneToken || err == auth.ErrInvalidToken {
				a.Implor.ResError(c, res.Err401Unauthorized)
				return // 无有效登陆用户
			} else if err == auth.ErrExpiredToken {
				a.Implor.ResError(c, res.Err456TokenExpired)
				return // 访问令牌已经过期
			}
			a.Implor.ResError(c, res.Err500InternalServer)
			return // 解析jwt令牌出现未知错误
		}
		a.Implor.SetUserInfo(c, user)
		c.Next()
		return
	}
}
