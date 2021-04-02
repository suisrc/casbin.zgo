package casbin

import (
	"strings"
	"time"

	"github.com/suisrc/res.zgo"
)

//====================================
// func https://casbin.org/docs/zh-CN/function
//====================================

// DomainMatch func
func DomainMatch(key1 string, key2 string) bool {
	if key2[:1] == "." {
		return strings.HasSuffix(key1, key2)
	}
	i := strings.Index(key2, "*") + 1
	if i == 0 {
		return key1 == key2
	}
	l := len(key2)
	if i == l {
		return true
	}
	if li := len(key1) - (l - i); li > 0 {
		// 截取key1可用部分
		return key1[li:] == key2[i:]
	}
	return key1 == key2[i:]
}

// DomainMatchFunc func
func DomainMatchFunc(args ...interface{}) (interface{}, error) {
	domain1 := args[0].(string)
	domain2 := args[1].(string)
	if domain2 == "" || domain2 == "*" {
		return true, nil
	}
	return DomainMatch(domain1, domain2), nil
}

// AudienceMatchFunc func
func AudienceMatchFunc(args ...interface{}) (interface{}, error) {
	domain1 := args[0].(string)
	domain2 := args[1].(string)
	audience := args[2].(string)
	if domain2 == "" || domain2 == "*" {
		return true, nil
	}
	if domain2 == "jwt" {
		return DomainMatch(domain1, audience), nil
	}
	return DomainMatch(domain1, domain2), nil
}

// MethodMatchFunc func
func MethodMatchFunc(args ...interface{}) (interface{}, error) {
	method := args[0].(string)
	methods := args[1].(string)
	if methods == "" || methods == "*" {
		return true, nil
	}
	return strings.Contains(methods, method), nil
}

// CustomMatchFunc func
func CustomMatchFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 3 {
		return false, nil
	}
	c8n, b := args[0].(string)
	if !b || c8n == "" {
		return false, nil
	}
	conditions := make(map[string]interface{})
	if err := res.JSONUnmarshal([]byte(c8n), &conditions); err != nil {
		// panic(err)
		// log.Println(err)
		return false, nil
		// return false, err
		// return false, &helper.ErrorModel{
		// 	Status:   403,
		// 	ShowType: helper.ShowWarn,
		// 	ErrorMessage: &i18n.Message{
		// 		ID:    "ERR-CASBIN-CONDITION",
		// 		Other: "验证器条件错误，拒绝访问",
		// 	},
		// }
	}
	// sub, b := args[1].(CasbinSubject)
	// if !b {
	// 	return false, nil
	// }
	// obj, b := args[2].(CasbinObject)
	// if !b {
	// 	return false, nil
	// }

	result := false
	if access, b := conditions["access_time"]; b {
		if r, e := customAccessTimes(access); e != nil || !r {
			return false, e // 条件失败
		}
		result = true
	}
	return result, nil
}

// 验证授权时间
func customAccessTimes(access interface{}) (bool, error) {
	if access2, b := access.(map[string]interface{}); b {
		if times, b := access2["times"]; b {
			if times2, b := times.([]interface{}); b && len(times2) == 2 {
				now := time.Now()
				if times2[0] != "" {
					if t, e := time.ParseInLocation("2006-01-02 15:04:05", times2[0].(string), time.Local); e != nil {
						return false, nil
					} else if t.After(now) {
						return false, nil
					}
				}
				if times2[1] != "" {
					if t, e := time.ParseInLocation("2006-01-02 15:04:05", times2[1].(string), time.Local); e != nil {
						return false, nil
					} else if t.Before(now) {
						return false, nil
					}
				}
				// log.Println(access)
				return true, nil
			}
		}
	}
	return false, nil
}

// HasSuffixFunc func
func HasSuffixFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, nil
	}
	if str, ok := args[0].(string); !ok {
		return false, nil
	} else if suf, ok := args[1].(string); !ok {
		return false, nil
	} else {
		return strings.HasSuffix(str, suf), nil
	}
}

// HasPrefixFunc func
func HasPrefixFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, nil
	}
	if str, ok := args[0].(string); !ok {
		return false, nil
	} else if pre, ok := args[1].(string); !ok {
		return false, nil
	} else {
		return strings.HasPrefix(str, pre), nil
	}
}
