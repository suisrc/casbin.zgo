package casbin

import (
	"github.com/jmoiron/sqlx"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/suisrc/auth.zgo"
	"github.com/suisrc/config.zgo"
	"github.com/suisrc/logger.zgo"
	"github.com/suisrc/res.zgo"
)

// Implor 外部需要实现的接口
type Implor interface {
	GetAuther() auth.Auther
	GetStorer() res.Storer
	GetTable() string
	GetSqlx2() *sqlx.DB
	GetSuperUserCode() string
	GetPlatformCode() string
	GetClientIP() string
	GetClientUA() string
	UpdateModelEnable(mid int64) error
	QueryPolicies(org, ver string) (*Policy, error)
	QueryServiceCode(ctx res.Context, user auth.UserInfo, host, path, org string) (string, int64, error)
	CheckTenantService(ctx res.Context, user auth.UserInfo, org, svc string, sid int64) (bool, error)

	SetHeader(ctx res.Context, key, value string)
	SetUserInfo(ctx res.Context, usr auth.UserInfo)
	ResError(ctx res.Context, err *res.ErrorModel)
	FixError(ctx res.Context, status int, err error, fun func()) bool
}

// 角色定义：
// 1.用户在租户和租户应用上有且各自具有一个角色
// 2.如果在同一个位置(租户或应用)上有多个角色， 服务直接拒绝
// 3.子应用角色优先于租户角色(名称排他除外)
// 3.子应用可以使用使用X-Request-Svc-[SVC-NAME]-Role指定服务角色， 且角色有限被使用

// UseAuthCasbinMiddlewareByOrigin 用户授权中间件
func (a *Auther) AuthCasbinMiddlewareByOrigin(c res.Context, conf config.Casbin, xget func(res.Context, string) (string, error)) {

	user, err := a.Implor.GetAuther().GetUserInfo(c, "")
	if err != nil {
		if err == auth.ErrNoneToken || err == auth.ErrInvalidToken {
			//res.ResError(c, res.Err401Unauthorized)
			a.Implor.ResError(c, res.Err401Unauthorized)
			return // 无有效登陆用户
		} else if err == auth.ErrExpiredToken {
			a.Implor.ResError(c, res.Err456TokenExpired)
			return // 访问令牌已经过期
		}
		a.Implor.ResError(c, res.Err500InternalServer)
		return // 解析jwt令牌出现未知错误
	}
	if !conf.Enable {
		// 禁用了jwt功能
		a.Implor.SetUserInfo(c, user)
		c.Next()
		return
	}
	// 获取访问的域名和路径
	var host, path string // casbin -> 参数
	if host, err = xget(c, res.XReqOriginHostKey); err != nil {
		a.Implor.ResError(c, res.Err403Forbidden)
		return
	}
	if path, err = xget(c, res.XReqOriginPathKey); err != nil {
		a.Implor.ResError(c, res.Err403Forbidden)
		return
	}

	// 获取用户访问的服务
	org := user.GetOrgCode()                                             // casbin -> 参数
	svc, sid, err := a.Implor.QueryServiceCode(c, user, host, path, org) // casbin -> 参数
	if err != nil {
		if err.Error() == "no service" {
			// 访问的服务在权限系统中不存在
			// res.ResError(c, res.Err403Forbidden)
			a.Implor.ResError(c, &res.ErrorModel{
				Status:   403,
				ShowType: res.ShowWarn,
				ErrorMessage: &i18n.Message{
					ID:    "ERR-SERVICE-NONE",
					Other: "访问的应用不存在",
				},
			})
		} else {
			a.Implor.FixError(c, 500, err, func() { logger.Errorf(c, logger.ErrorWW(err)) }) // 未知错误
		}
		return
	}
	a.Implor.SetHeader(c, "X-Request-Z-Svc", svc)
	// 验证服务可访问下
	if b, err := a.Implor.CheckTenantService(c, user, org, svc, sid); err != nil {
		a.Implor.FixError(c, 500, err, func() { logger.Errorf(c, logger.ErrorWW(err)) }) // 未知错误
		return
	} else if !b {
		// 租户无法访问该服务
		a.Implor.ResError(c, &res.ErrorModel{
			Status:   403,
			ShowType: res.ShowWarn,
			ErrorMessage: &i18n.Message{
				ID:    "ERR-SERVICE-CLOSE",
				Other: "服务未开通",
			},
		})
		return // 处理过程中发生未知异常
	}
	// 验证用户是否可以跳过权限验证
	if b, err := a.IsPassPermission(c, user, org, svc); err != nil {
		a.Implor.FixError(c, 403, err, func() { logger.Errorf(c, logger.ErrorWW(err)) }) // 未知错误
		return
	} else if b {
		// 跳过权限判断
		a.Implor.SetUserInfo(c, user)
		c.Next()
		return
	}

	// 获取用户访问角色
	role, err := a.GetUserRole(c, user, svc, org)
	if err != nil {
		a.Implor.FixError(c, 403, err, func() { logger.Errorf(c, logger.ErrorWW(err)) })
		return
	}
	if role == "" {
		a.Implor.ResError(c, &res.ErrorModel{
			Status:   403,
			ShowType: res.ShowWarn,
			ErrorMessage: &i18n.Message{
				ID:    "ERR-SERVICE-NOROLE",
				Other: "用户没有可用角色，拒绝访问",
			},
		})
		return
	}
	a.Implor.SetHeader(c, "X-Request-Z-Svc-Role", role)

	// 租户用户， 默认我们认为租户用户范围不会超过100,000 所以会间人员信息加载到认证器中执行
	// _, _, _ := service.DecryptAccountWithUser(c, user.GetAccount(), user.GetTokenID())
	sub := Subject{
		// UsrID:    aid,
		// AccID:    uid,
		Role:   role,                   // casbin -> 参数 角色
		Acc1:   user.GetAccount1(),     // casbin -> 参数 系统ID
		Acc2:   user.GetAccount2(),     // casbin -> 参数 租户自定义ID
		Usr:    user.GetUserID(),       // casbin -> 参数 用户ID
		Org:    org,                    // casbin -> 参数 租户
		OrgUsr: user.GetOrgUsrID(),     // casbin -> 参数 租户自定义ID
		Iss:    user.GetIssuer(),       // casbin -> 参数 授控域
		Aud:    user.GetAudience(),     // casbin -> 参数 受控域
		Agent:  user.GetAgent(),        // casbin -> 参数 应用ID
		Scope:  user.GetScope(),        // casbin -> 参数 作用域
		Cip:    a.Implor.GetClientIP(), // casbin -> 参数 client ip
		Cua:    a.Implor.GetClientUA(), // casbin -> 参数 client user agent
	}
	// 访问资源
	method, _ := xget(c, res.XReqOriginMethodKey)
	obj := Object{
		Svc:    svc,    // casbin -> 参数 服务
		Host:   host,   // casbin -> 参数 请求域名
		Path:   path,   // casbin -> 参数 请求路径
		Method: method, // casbin -> 参数 请求方法
	}
	// fix prefix for casbin
	if sub.Usr != "" {
		sub.Usr = UserPrefix + sub.Usr
	}
	if sub.OrgUsr != "" {
		sub.OrgUsr = UserPrefix + sub.OrgUsr
	}
	if sub.Role != "" {
		sub.Role = RolePrefix + sub.Role
	}

	if enforcer, err := a.GetEnforcer(c, user, svc, org); err != nil {
		if a.Implor.FixError(c, 0, err, nil) {
			return
		}
		logger.Errorf(c, logger.ErrorWW(err))
		a.Implor.ResError(c, &res.ErrorModel{
			Status:   403,
			ShowType: res.ShowWarn,
			ErrorMessage: &i18n.Message{
				ID:    "ERR-CASBIN-BUILD",
				Other: "权限验证器发生异常，拒绝访问",
			},
		})
		return
	} else if enforcer == nil {
		// 授权发生异常, 没有可用权限验证器
		a.Implor.ResError(c, res.Err403Forbidden)
		return
	} else if b, err := enforcer.Enforce(sub, obj); err != nil {
		if a.Implor.FixError(c, 0, err, nil) {
			return
		}
		logger.Errorf(c, logger.ErrorWW(err))
		a.Implor.ResError(c, &res.ErrorModel{
			Status:   403,
			ShowType: res.ShowWarn,
			ErrorMessage: &i18n.Message{
				ID:    "ERR-CASBIN-VERIFY",
				Other: "权限验证器发生异常，拒绝访问",
			},
		})
		return
	} else if !b {
		// 授权失败， 拒绝访问
		// log.Println(ros)
		// log.Println(enforcer.GetImplicitPermissionsForUser(ros))
		a.Implor.ResError(c, res.Err403Forbidden)
		return
	}

	a.Implor.SetUserInfo(c, user)
	c.Next()
}
