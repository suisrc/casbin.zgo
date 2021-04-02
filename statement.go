package casbin

import "time"

// Object subject
type Object struct {
	Svc    string
	Host   string
	Path   string
	Method string
}

// Subject subject
type Subject struct {
	//UsrID    int
	//AccID    int
	Role   string
	Acc1   string
	Acc2   string
	Usr    string
	Org    string
	OrgUsr string
	Iss    string
	Aud    string
	Agent  string
	Scope  string
	Cip    string
	Cua    string
}

var (
	// PolicyModel casbin使用的对比模型
	PolicyModel = `[request_definition]
r = sub, obj

[policy_definition]
p = sub, svc, org, path, method, eft, c8n

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = `
	// DefaultMatcher casbin使用的对比模型
	DefaultMatcher = `(p.sub=="r:login" || g(r.sub.Role, p.sub)) && r.obj.Svc==p.svc && (p.method=="" || method(r.obj.Method, p.method)) && (p.path=="" || path(r.obj.Path, p.path)) && (p.c8n=="" || custom(p.c8n, r.sub, r.obj))`
)

var (
	// CachedExpireAt 缓存定时器刷新时间
	CachedExpireAt = 4 * time.Minute
	// EnforcerCheckAt 引擎检测版本时间
	EnforcerCheckAt = 2 * time.Minute
	// EnforcerExpireAt 引擎标记过期时间
	EnforcerExpireAt = 8 * time.Minute
	// ServiceCodeExpireAt 服务缓存过期时间
	ServiceCodeExpireAt = 2 * time.Minute
	// ServiceTenantExpireAt 租户缓存过期时间
	ServiceTenantExpireAt = 2 * time.Minute
)

var (
	// SvcRoleKey 角色配置
	SvcRoleKey = "X-Request-Svc-%s-Role" // "X-Request-Svc-[service name]-Role"
	// SysRoleKey 系统平台角色
	SysRoleKey = "X-Request-Sys-Role"
	// SvcPublic 公共服务
	SvcPublic = "pub-"
	// RolePrefix 角色
	RolePrefix = "r:"
	// UserPrefix 用户
	UserPrefix = "u:"
	// PolicyPrefix 策略
	PolicyPrefix = "p:"
	// ActionPrefix 策略
	ActionPrefix = "a:"
	// SourcePrefix 策略
	SourcePrefix = "s:"
	// // NoSign 未登陆
	// NoSign = "nosign"
	// // NoRole 无角色
	// NoRole = "norole"
	// // NoUser 无用户
	// NoUser = "nouser"
)
