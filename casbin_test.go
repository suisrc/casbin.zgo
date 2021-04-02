package casbin_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suisrc/casbin.zgo"
)

func TestAuth(t *testing.T) {
	b, err := casbin.DomainMatchFunc("", "a.cn", "a.cn")
	assert.Nil(t, err)
	assert.True(t, b.(bool))

	b, err = casbin.DomainMatchFunc("", "a.a.cn", "*.a.cn")
	assert.Nil(t, err)
	assert.True(t, b.(bool))

	b, err = casbin.DomainMatchFunc(".a.cn", "a.a.cn", "jwt")
	assert.Nil(t, err)
	assert.True(t, b.(bool))

	b, err = casbin.DomainMatchFunc(".a.cn", "a.a.cn", "")
	assert.Nil(t, err)
	assert.True(t, b.(bool))
}

func TestAuth2(t *testing.T) {
	ls := 3
	log.Printf(fmt.Sprintf("%t", ls&(1<<0) > 0))
	assert.NotNil(t, nil)
}
