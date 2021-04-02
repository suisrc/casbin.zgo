package casbin

import (
	"errors"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/util"
	"github.com/suisrc/auth.zgo"
	"github.com/suisrc/res.zgo"
)

// Auther 权限管理
type Auther struct {
	Implor         Implor
	CachedEnforcer map[string]*Enforcer // 验证器
	CachedExpireAt time.Time            // 刷新时间
	Mutex          sync.RWMutex         // 同步锁
}

// Enforcer 验证器
type Enforcer struct {
	Enforcer *casbin.SyncedEnforcer // 验证器
	ExpireAt time.Time              // 过期时间
	CheckAt  time.Time              // 刷新时间
	Version  string                 // 验证版本
	Mutex    sync.RWMutex           // 同步锁
	Check    bool
}

// Policy 策略
type Policy struct {
	Mid       int64
	Ver       string
	New       bool                           // 重新构建
	ModelText string                         // 模型声明
	Grouping  map[string]map[string]bool     // 角色声明
	Policies  map[string]map[string][]string // 策略声明
	Version   string                         // 策略版本
}

// GetGrouping ...
func (a *Policy) GetGrouping() *[][]string {
	res := [][]string{}
	for k1, v1 := range a.Grouping {
		for k2, v2 := range v1 {
			if v2 {
				res = append(res, []string{k1, k2})
			}
		}
	}
	return &res
}

// GetPolicies ...
func (a *Policy) GetPolicies() *[][]string {
	res := [][]string{}
	for _, ps := range a.Policies {
		for _, p := range ps {
			res = append(res, p)
		}
	}
	return &res
}

// ConvertMapToArray ...
func ConvertMapToArray(data *map[string]map[string][]string) *[][]string {
	res := [][]string{}
	for _, ds := range *data {
		for _, d := range ds {
			res = append(res, d)
		}
	}
	return &res
}

// ClearEnforcer 清理缓存
// 缓存全部情况后， 引擎立即完成刷新操作
func (a *Auther) ClearEnforcer(force bool, org string) {
	if a.CachedEnforcer == nil {
		// do nothing
	} else if force {
		a.CachedEnforcer = map[string]*Enforcer{}         // 删除之前所有的
		a.CachedExpireAt = time.Now().Add(CachedExpireAt) // 设定04分钟后刷新
	} else if org != "" {
		key := "zgo:casbin:" + org
		delete(a.CachedEnforcer, key) // 清除指定缓存
	} else {
		now := time.Now()
		for k, v := range a.CachedEnforcer {
			if v.ExpireAt.Before(now) {
				delete(a.CachedEnforcer, k) // 清除过期缓存
			}
		}
	}
}

// GetEnforcer 获取验证控制器
func (a *Auther) GetEnforcer(c res.ReqContext, user auth.UserInfo, svc, org string) (*casbin.SyncedEnforcer, error) {
	if a.CachedEnforcer == nil {
		a.CachedEnforcer = map[string]*Enforcer{}
		a.CachedExpireAt = time.Now().Add(CachedExpireAt)
	} else if a.CachedExpireAt.Before(time.Now()) {
		a.CachedExpireAt = time.Now().Add(CachedExpireAt) // 设定04分钟后刷新
		defer func() { go a.ClearEnforcer(false, "") }()  // 执行异步刷新流程
	}
	key := "zgo:casbin:" + org
	ver := ""
	cached, exist := a.CachedEnforcer[key]
	if exist && cached.CheckAt.After(time.Now()) {
		// c.Writer.Header().Set("X-Request-Z-Casbin-Ver", cached.Version)
		a.Implor.SetHeader(c, "X-Request-Z-Casbin-Ver", cached.Version)
		if !cached.Check {
			// 执行异步刷新流程, 在引擎还有1/2时间过期的时候， 该刷新非阻塞异步刷新
			ca := cached.CheckAt.Sub(time.Now())
			// 为系统刷新留出8秒时间， 如果过期间隔小于8s， 不刷新， 将使用同步刷新策略，
			// 这是防止同步刷新和异步刷新同时进行的策略保护
			// 系统默认引擎版本检查是60秒， 也就是说，
			// 引擎更新时间最快为30秒，
			// 异步更新时间为30~52秒之间，
			// 同步刷新在52秒之后，
			// 如果引擎在600秒没有被使用， 将会被释放
			if 8*time.Second < ca && ca < EnforcerCheckAt/2 {
				ver = cached.Version
				go a.GetEnforcer2(user, cached, svc, org, key, ver)
			}
		}
		return cached.Enforcer, nil
	} else if exist {
		ver = cached.Version
		// 多进程更新
		defer cached.Mutex.Unlock()
		cached.Mutex.Lock()
		if c2, e2 := a.CachedEnforcer[key]; e2 && c2.CheckAt.After(time.Now()) {
			a.Implor.SetHeader(c, "X-Request-Z-Casbin-Ver", c2.Version)
			return c2.Enforcer, nil // 缓存已经由其他进程更新
		}
	} else {
		// 多进程创建
		defer a.Mutex.Unlock()
		a.Mutex.Lock()
		if c2, e2 := a.CachedEnforcer[key]; e2 {
			a.Implor.SetHeader(c, "X-Request-Z-Casbin-Ver", c2.Version)
			return c2.Enforcer, nil // 缓存已经由其他进程更新
		}

	}
	// 处理结果
	if efc, err := a.GetEnforcer2(user, cached, svc, org, key, ver); err != nil {
		return nil, err
	} else if efc != nil {
		if cached != nil {
			a.Implor.SetHeader(c, "X-Request-Z-Casbin-Ver", cached.Version)
		} else if c2, e2 := a.CachedEnforcer[key]; e2 {
			a.Implor.SetHeader(c, "X-Request-Z-Casbin-Ver", c2.Version)
		}
		return efc, nil
	}
	return nil, errors.New("no casbin enforcer")
}

// GetEnforcer2 获取验证控制器
func (a *Auther) GetEnforcer2(user auth.UserInfo, cached *Enforcer, svc, org, key, ver string) (*casbin.SyncedEnforcer, error) {
	if cached != nil {
		defer func() { cached.Check = false }()
		cached.Check = true
	}
	// 执行更新
	if cps, err := a.Implor.QueryPolicies(org, ver); err != nil {
		return nil, err
	} else if cached != nil && cps == nil {
		// 版本不变, 重置有效期限， 不需要任何修改
		cached.CheckAt = time.Now().Add(EnforcerCheckAt)
		cached.ExpireAt = cached.CheckAt.Add(EnforcerExpireAt)
		return cached.Enforcer, nil
	} else if cps == nil {
		// 系统发生异常， 无法更新配置
		return nil, errors.New("casbin policy is nil")
	} else if cached != nil && !cps.New {
		// 重新加载配置, *Adapter
		// 数据库访问适配器（使用redis缓存请改写这里）
		if adapter, b := cached.Enforcer.GetAdapter().(*Adapter); b {
			if adapter.Mid != cps.Mid || adapter.Ver != cps.Ver {
				adapter.Mid = cps.Mid
				adapter.Ver = cps.Ver
			}
		} else {
			return nil, errors.New("casbin adapter type is error")
		}
		cached.Enforcer.LoadPolicy()
		cached.CheckAt = time.Now().Add(EnforcerCheckAt)
		cached.ExpireAt = cached.CheckAt.Add(EnforcerExpireAt)
		cached.Version = cps.Version
		return cached.Enforcer, nil
	} else {
		// 构建新的内容编排
		// log.Println(c)
		m, err := model.NewModelFromString(cps.ModelText)
		if err != nil {
			return nil, err
		}
		// *Adapter
		// 数据库访问适配器（使用redis缓存请改写这里）
		adapter := NewCasbinAdapter(a.Implor.GetSqlx2(), a.Implor.GetTable(), cps.Mid, cps.Ver)
		// 构建新的认证引擎
		e, err := casbin.NewSyncedEnforcer(m, adapter)
		if err != nil {
			return nil, err
		}
		// e.EnableLog(conf.Debug)
		// e.EnableEnforce(conf.Enable)
		// 注册方法
		e.AddFunction("domain", DomainMatchFunc)
		e.AddFunction("method", MethodMatchFunc)
		e.AddFunction("custom", CustomMatchFunc)
		e.AddFunction("prefix", HasPrefixFunc)
		e.AddFunction("suffix", HasSuffixFunc)
		e.AddFunction("ipmask", util.IPMatchFunc)
		e.AddFunction("path", util.KeyMatchFunc)
		e.AddFunction("regex", util.RegexMatchFunc)

		// fm.AddFunction("keyMatch", util.KeyMatchFunc)
		// fm.AddFunction("keyGet", util.KeyGetFunc)
		// fm.AddFunction("keyMatch2", util.KeyMatch2Func)
		// fm.AddFunction("keyGet2", util.KeyGet2Func)
		// fm.AddFunction("keyMatch3", util.KeyMatch3Func)
		// fm.AddFunction("keyMatch4", util.KeyMatch4Func)
		// fm.AddFunction("regexMatch", util.RegexMatchFunc)
		// fm.AddFunction("ipMatch", util.IPMatchFunc)
		// fm.AddFunction("globMatch", util.GlobMatchFunc)

		adapter.Enable = true // 启动适配器
		if !cps.New {
			e.LoadPolicy() // 通过策略持久化适配器加载
		} else {
			// 增加策略关系
			if _, err := e.AddNamedPolicies("p", *cps.GetPolicies()); err != nil {
				return nil, err
			}
			// 增加策略关系
			if _, err := e.AddNamedGroupingPolicies("g", *cps.GetGrouping()); err != nil {
				return nil, err
			}
			// 保存策略关系
			if err := e.SavePolicy(); err != nil {
				return nil, err
			}
			// 更新状态
			if err := a.Implor.UpdateModelEnable(cps.Mid); err != nil {
				return nil, err
			}
		}

		// 配置缓存
		a.CachedEnforcer[key] = &Enforcer{
			Enforcer: e,
			CheckAt:  time.Now().Add(EnforcerCheckAt),  // 刷新期1分钟
			ExpireAt: time.Now().Add(EnforcerExpireAt), // 有效期8分钟
			Version:  cps.Version,
		}
		return e, nil
	}
}
