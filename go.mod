module github.com/suisrc/casbin.zgo

go 1.16

require (
	github.com/casbin/casbin/v2 v2.25.5
	github.com/jmoiron/sqlx v1.3.1
	github.com/kr/pretty v0.1.0 // indirect
	github.com/nicksnyder/go-i18n/v2 v2.1.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/suisrc/auth.zgo v0.0.0
	github.com/suisrc/config.zgo v0.0.0
	github.com/suisrc/logger.zgo v0.0.0
	github.com/suisrc/res.zgo v0.0.0
	golang.org/x/sys v0.0.0-20210112080510-489259a85091 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace (
	github.com/suisrc/auth.zgo v0.0.0 => ../auth
	github.com/suisrc/buntdb.zgo v0.0.0 => ../buntdb
	github.com/suisrc/config.zgo v0.0.0 => ../config
	github.com/suisrc/crypto.zgo v0.0.0 => ../crypto
	github.com/suisrc/logger.zgo v0.0.0 => ../logger
	github.com/suisrc/res.zgo v0.0.0 => ../res
)
