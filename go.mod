module github.com/suisrc/casbin.zgo

go 1.16

// replace (
// 	github.com/suisrc/auth.zgo => ../auth
// 	github.com/suisrc/buntdb.zgo => ../buntdb
// 	github.com/suisrc/config.zgo => ../config
// 	github.com/suisrc/crypto.zgo => ../crypto
// 	github.com/suisrc/logger.zgo => ../logger
// 	github.com/suisrc/res.zgo => ../res
// )

require (
	github.com/casbin/casbin/v2 v2.25.5
	github.com/jmoiron/sqlx v1.3.1
	github.com/kr/pretty v0.1.0 // indirect
	github.com/nicksnyder/go-i18n/v2 v2.1.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/suisrc/auth.zgo v0.0.0-20210408060712-08bb878db327
	github.com/suisrc/config.zgo v0.0.0-20210407020836-a5a7e3c8595d
	github.com/suisrc/logger.zgo v0.0.0-20210408054212-b4e804e2dc15
	github.com/suisrc/res.zgo v0.0.0-20210408020700-20221959252e
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)
