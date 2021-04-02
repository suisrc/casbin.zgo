package casbin

import (
	"database/sql"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

// Rule ...
type Rule struct {
	Mid int64          `db:"mid"`
	Ver string         `db:"ver"`
	PT  string         `db:"p_type"`
	V0  sql.NullString `db:"v0"`
	V1  sql.NullString `db:"v1"`
	V2  sql.NullString `db:"v2"`
	V3  sql.NullString `db:"v3"`
	V4  sql.NullString `db:"v4"`
	V5  sql.NullString `db:"v5"`
	V6  sql.NullString `db:"v6"`
	V7  sql.NullString `db:"v7"`
	V8  sql.NullString `db:"v8"`
	V9  sql.NullString `db:"v9"`
	CT  sql.NullTime   `db:"created_at"`
}

// Adapter 适配器
type Adapter struct {
	DB2    *sqlx.DB // database
	Tbl    string   //table name
	Mid    int64    // model id
	Ver    string   // model ver
	Enable bool     // 是否启用适配器
}

// var _ persist.BatchAdapter = (*Adapter)(nil)
// var _ persist.FilteredAdapter = (*Adapter)(nil)

// NewCasbinAdapter is the constructor for Adapter with existed connection
func NewCasbinAdapter(db2 *sqlx.DB, tbl string, mid int64, ver string) *Adapter {
	a := &Adapter{
		DB2: db2,
		Tbl: tbl,
		Mid: mid,
		Ver: ver,
	}
	a.ensureTable()
	// runtime.SetFinalizer(a, finalizer)
	return a
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(m model.Model) error {
	if !a.Enable {
		return nil // 未启用， 阻止第一次加载
	}
	rules, err := a.queryPolicies()
	if err != nil {
		return err
	}
	for _, rule := range *rules {
		key := rule.PT
		sec := key[:1]
		args := []string{}

		obj := reflect.ValueOf(rule)
		withColumnsIterator(func(c string, i int) (string, error) {
			if c != "ver" && c[:1] == "v" {
				if _, err := strconv.Atoi(c[1:]); err == nil {
					if arg, b := obj.Field(i).Interface().(sql.NullString); b {
						if arg.Valid {
							args = append(args, arg.String)
						} else {
							return "", errors.New("end assignment") // 结束遍历
						}
					}
				}
			}
			return "", nil
		}, rule)

		m[sec][key].Policy = append(m[sec][key].Policy, args)
		m[sec][key].PolicyMap[strings.Join(args, model.DefaultSep)] = len(m[sec][key].Policy) - 1
		// persist.LoadPolicyLine("", m)
	}
	return nil
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) (err error) {
	if !a.Enable {
		return nil // 未启用， 阻止持久化
	}
	err = withTx(a.DB2, func(tx *sqlx.Tx) (err error) {
		lines := []Rule{}
		for ptype, ast := range model["p"] {
			for _, rule := range ast.Policy {
				line := a.createPolicyRule(ptype, rule)
				line.CT = sql.NullTime{Valid: true, Time: time.Now()}
				lines = append(lines, line)
			}
		}
		for ptype, ast := range model["g"] {
			for _, rule := range ast.Policy {
				line := a.createPolicyRule(ptype, rule)
				line.CT = sql.NullTime{Valid: true, Time: time.Now()}
				lines = append(lines, line)
			}
		}
		if err = a.clearPolicyRules(tx); err != nil {
			return
		}
		if err = a.insertPolicyRules(tx, &lines); err != nil {
			return
		}
		return
	})
	return
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) (err error) {
	return
	// line := a.createPolicyRule(ptype, rule)
	// err = a.insertPolicyLine(&line)
	// if err != nil {
	// 	return
	// }
	// return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) (err error) {
	return
	// line := a.createPolicyRule(ptype, rule)
	// err = a.deletePolicyLine(&line)
	// if err != nil {
	// 	return
	// }
	// return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (err error) {
	return
}

// AddPolicies adds policy rules to the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) (err error) {
	return
}

// RemovePolicies removes policy rules from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) (err error) {
	return
}

func (a *Adapter) ensureTable() {
	_, err := a.DB2.Exec(fmt.Sprintf("SELECT 1 FROM `%s` LIMIT 1", a.Tbl))
	if err != nil {
		panic(err)
	}
}

func (a *Adapter) queryPolicies() (rules *[]Rule, err error) {
	rules = new([]Rule)
	query := fmt.Sprintf("SELECT * FROM `%s` WHERE mid = ? and ver = ?", a.Tbl)
	err = a.DB2.Select(rules, query, a.Mid, a.Ver)
	// for _, r := range *rules {
	// 	log.Println(r)
	// }
	return
}

func (a *Adapter) insertPolicyRules(db *sqlx.Tx, lines *[]Rule) (err error) {
	if lines == nil || len(*lines) == 0 {
		return nil
	}

	columns := strings.Builder{}
	values := strings.Builder{}
	withColumnsItr(func(c string) string {
		columns.WriteString(",")
		columns.WriteString(c)
		values.WriteString(",:")
		values.WriteString(c)
		return ""
	}, (*lines)[0])
	// for _, line := range *lines {
	// 	line.CT = sql.NullTime{Valid: true, Time: time.Now()}
	// }
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", a.Tbl, columns.String()[1:], values.String()[1:])
	_, err = db.NamedExec(query, *lines)
	if err != nil {
		return
	}
	return
}

func (a *Adapter) clearPolicyRules(db *sqlx.Tx) (err error) {
	query := fmt.Sprintf("DELETE FROM %s WHERE mid = ? AND ver = ?", a.Tbl)
	_, err = db.Exec(query, a.Mid, a.Ver)
	return
}

func (a *Adapter) createPolicyRule(ptype string, rule []string) Rule {
	line := Rule{}
	line.Mid = a.Mid
	line.Ver = a.Ver
	line.PT = ptype

	obj := reflect.ValueOf(&line).Elem()
	withColumnsIterator(func(c string, i int) (string, error) {
		if c != "ver" && c[:1] == "v" {
			if idx, err := strconv.Atoi(c[1:]); err == nil {
				if idx < len(rule) {
					// v.Field(i).SetString(rule[idx])
					arg := sql.NullString{Valid: true, String: rule[idx]}
					obj.Field(i).Set(reflect.ValueOf(arg))
				} else {
					return "", errors.New("end assignment") // 结束遍历
				}
			}
		}
		return "", nil
	}, line)
	return line
}

// WithColumnsItr column
func withColumnsItr(iterater func(string) string, obj interface{}) ([]string, error) {
	return withColumnsIterator(func(c string, i int) (string, error) { return iterater(c), nil }, obj)
}

// WithColumnsIterator column
func withColumnsIterator(iterater func(string, int) (string, error), obj interface{}) ([]string, error) {
	result := []string{}
	t := reflect.TypeOf(obj)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return result, nil
	}

	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("db")
		if tag == "-" {
			continue
		}
		if idx := strings.Index(tag, ","); idx > 0 {
			tag = tag[:idx]
		}
		tag = strings.TrimSpace(tag)

		column := tag
		// if column == "" {
		// 	column = strings.ToLower(t.Field(i).Name)
		// }
		if iterater != nil {
			var err error
			column, err = iterater(column, i)
			if err != nil {
				return result, err
			}
		}
		if column != "" {
			result = append(result, column)
		}
	}
	return result, nil
}

// WithTx ...
func withTx(db *sqlx.DB, fn func(tx *sqlx.Tx) error) error {
	tx := db.MustBegin()
	defer func() {
		if v := recover(); v != nil {
			tx.Rollback()
			panic(v)
		}
	}()
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			err = errors.Wrapf(err, "rolling back transaction: %v", rerr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrapf(err, "committing transaction: %v", err)
	}
	return nil
}

// func (a *Adapter) rawDelete(line *Rule) (err error) {
// 	args := []interface{}{}
// 	columns := strings.Builder{}
//
// 	v := reflect.ValueOf(line)
// 	WithColumnsIterator(func(c string, i int) (string, error) {
// 		columns.WriteString("AND ")
// 		columns.WriteString(c)
// 		columns.WriteString(" = ?")
// 		args = append(args, v.Field(i).Interface())
// 		return "", nil
// 	}, line)
//
// 	query := fmt.Sprintf("DELETE FROM `%s` WHERE %s", a.Tbl, columns.String()[4:])
// 	_, err = a.DB.Exec(query, args...)
// 	if err != nil {
// 		return
// 	}
// 	return
// }
//
// func (a *Adapter) insertPolicyLine(line *Rule) (err error) {
// 	return a.insertPolicyLine2(a.DB, line)
// }
//
// func (a *Adapter) insertPolicyLine2(db *sqlx.DB, line *Rule) (err error) {
// 	columns := strings.Builder{}
// 	values := strings.Builder{}
// 	WithColumnsItr(func(c string) string {
// 		columns.WriteString(",")
// 		columns.WriteString(c)
// 		values.WriteString(",:")
// 		values.WriteString(c)
// 		return ""
// 	}, line)
// 	line.CT = sql.NullTime{Valid: true, Time: time.Now()}
// 	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", a.Tbl, columns.String()[1:], values.String()[1:])
// 	_, err = db.NamedExec(query, line)
// 	if err != nil {
// 		return
// 	}
// 	return
// }
//
// func (a *Adapter) deletePolicyLine(line *Rule) (err error) {
// 	return a.deletePolicyLine2(a.DB, line)
// }
//
// func (a *Adapter) deletePolicyLine2(db *sqlx.DB, line *Rule) (err error) {
// 	columns := strings.Builder{}
// 	WithColumnsItr(func(c string) string {
// 		columns.WriteString("AND ")
// 		columns.WriteString(c)
// 		columns.WriteString(" = :")
// 		columns.WriteString(c)
// 		return ""
// 	}, line)
// 	query := fmt.Sprintf("DELETE FROM %s WHERE %s", a.Tbl, columns.String()[4:])
// 	_, err = a.DB.NamedExec(query, line)
// 	if err != nil {
// 		return
// 	}
// 	return
// }
//
// // ClearPolicies ...
// func (a *Adapter) clearPolicies() (err error) {
// 	query := fmt.Sprintf("DELETE FROM %s WHERE mid = ? AND ver = ?", a.Tbl)
// 	_, err = a.DB.Exec(query, a.Mid, a.Ver)
// 	return
// }
//
