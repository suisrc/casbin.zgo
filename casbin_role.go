package casbin

import (
	"fmt"
	"strings"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/suisrc/auth.zgo"
	"github.com/suisrc/res.zgo"
)

// IsPassPermission 跳过权限判断
// 确定管理员身份， 这里是否担心管理员身份被篡改？如果签名密钥泄漏， 会发生签名篡改问题， 所以需要保密服务器签名密钥
func (a *Auther) IsPassPermission(c res.Context, user auth.UserInfo, svc, org string) (bool, error) {
	if user.GetOrgAdmin() == a.Implor.GetSuperUserCode() {
		// 组织管理员， 跳过验证
		return true, nil
	} else if user.GetOrgCode() == a.Implor.GetPlatformCode() {
		// 平台用户， 暂不处理
	} else if user.GetOrgCode() == "" {
		// 无租户用户, 只验证登录， 注意：无组织用户只能访问pub服务
		if strings.HasPrefix(svc, SvcPublic) {
			return true, nil
		}
		return false, &res.ErrorModel{
			Status:   403,
			ShowType: res.ShowWarn,
			ErrorMessage: &i18n.Message{
				ID:    "ERR-SERVICE-TENANT-NONE",
				Other: "无租户信息，拒绝访问",
			},
		}
	}
	return false, nil
}

// GetUserRole 获取验证控制器
func (a *Auther) GetUserRole(c res.Context, user auth.UserInfo, svc, org string) (role string, err error) {
	if roles := user.GetUserRoles(); len(roles) == 0 {
		// 当前用户没有可用角色
		return "", nil
	} else if len(roles) == 1 {
		// 当前用户只有一个角色
		return roles[0], nil
	}
	// 处理多角色问题
	roles := []string{}
	if svc != "" && svc != a.Implor.GetPlatformCode() {
		role = c.GetHeader(fmt.Sprintf(SvcRoleKey, svc)) // 子应用， 需要子应用授权
		if role != "" {
			// 验证角色信息， 快速结束
			for _, v := range user.GetUserRoles() {
				if role == v {
					return role, nil // 角色有效直接返回
				}
			}
		}
		// 无指定角色， 获取用户服务角色
		roles = user.GetUserSvcRoles(svc) // 有可能没有角色信息， 使用len(roles) == 0判断没有应用角色
	}
	if role == "" && len(roles) == 0 {
		role = c.GetHeader(SysRoleKey) // 使用系统平台角色
		if role != "" {
			// 验证角色信息， 快速结束
			for _, v := range user.GetUserRoles() {
				if role == v {
					return role, nil // 角色有效直接返回
				}
			}
		}
		// 无指定角色， 获取用户服务角色
		roles = user.GetUserRoles()
	}
	if role != "" {
		// 指定的角色无效
		err = &res.ErrorModel{
			Status:   403,
			ShowType: res.ShowWarn,
			ErrorMessage: &i18n.Message{
				ID:    "ERR-SERVICE-ROLE-INVALID",
				Other: "用户指定的角色无效",
			},
		}
	} else if len(roles) == 1 {
		role = roles[0] // 只有单角色， 配置用户角色
	} else if len(roles) > 1 {
		// 用户对同一个应用具有多个角色， 拒绝访问
		err = &res.ErrorModel{
			Status:   403,
			ShowType: res.ShowWarn,
			ErrorMessage: &i18n.Message{
				ID:    "ERR-SERVICE-ROLE-MULT",
				Other: "用户访问的应用同时具有多角色，且没有指定角色",
			},
		}
	}
	return
}
