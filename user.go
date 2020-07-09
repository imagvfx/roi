package roi

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var CreateTableIfNotExistsUsersStmt = `CREATE TABLE IF NOT EXISTS users (
	username STRING UNIQUE NOT NULL CHECK (length(username) > 0) CHECK (username NOT LIKE '% %'),
	domain STRING UNIQUE NOT NULL,
	display_name STRING NOT NULL,
	team STRING NOT NULL,
	role STRING NOT NULL,
	email STRING NOT NULL,
	phone_number STRING NOT NULL,
	entry_date STRING NOT NULL,
	hashed_password STRING NOT NULL,
	current_show STRING NOT NULL,
	CONSTRAINT users_pk PRIMARY KEY (username, domain)
)`

// userInfo는 db에 저장하는 사용자 전체 정보이다.
type userInfo struct {
	User        string `db:"username"`
	Domain      string `db:"domain"`
	DisplayName string `db:"display_name"`
	Team        string `db:"team"`
	Role        string `db:"role"`
	Email       string `db:"email"`
	PhoneNumber string `db:"phone_number"`
	EntryDate   string `db:"entry_date"`

	HashedPassword string `db:"hashed_password"`

	// 설정
	CurrentShow string `db:"current_show"`
}

var userdbkey string = strings.Join(dbKeys(&userInfo{}), ", ")
var userdbidx string = strings.Join(dbIdxs(&userInfo{}), ", ")
var _ []interface{} = dbVals(&userInfo{})

// User는 일반적인 사용자 정보이다.
type User struct {
	User        string `db:"username"`
	Domain      string `db:"domain"`
	DisplayName string `db:"display_name"`
	Team        string `db:"team"`
	Role        string `db:"role"`
	Email       string `db:"email"`
	PhoneNumber string `db:"phone_number"`
	EntryDate   string `db:"entry_date"`
}

var userDBKey string = strings.Join(dbKeys(&User{}), ", ")
var userDBIdx string = strings.Join(dbIdxs(&User{}), ", ")
var _ []interface{} = dbVals(&User{})

// ID는 사용자의 아이디를 반환한다.
func (u *User) ID() string {
	if u.Domain != "" {
		return u.User + "@" + u.Domain
	}
	return u.User
}

// splitUserID는 사용자 아이디에서 유저이름과 도메인을 분리한다.
// 받아들인 아이디가 지원하지 않는 형식이라면 에러를 반환한다.
func splitUserID(id string) (user, domain string, err error) {
	if strings.ContainsAny(id, " \t\n") {
		return "", "", BadRequest("id must not contain spaces")
	}
	idparts := strings.Split(id, "@")
	if len(idparts) > 2 {
		return "", "", BadRequest("id must not contain more than one '@'")
	}
	user = idparts[0]
	if len(idparts) == 2 {
		domain = idparts[1]
	}
	err = verifyUserName(user)
	if err != nil {
		return "", "", err
	}
	err = verifyUserDomain(domain)
	if err != nil {
		return "", "", err
	}
	return user, domain, nil
}

// verifyUserName은 사용자의 이름을 확인하고 유효하지 않다면 에러를 낸다.
func verifyUserName(user string) error {
	if user == "" {
		return BadRequest("need user name")
	}
	return nil
}

// verifyUserName은 사용자의 도메인을 확인하고 유효하지 않다면 에러를 낸다.
func verifyUserDomain(domain string) error {
	// 로컬 유저는 도메인을 가지지 않는다.
	if domain == "" {
		return nil
	}
	// OIDC 유저
	if !strings.Contains(domain, ".") {
		return BadRequest("domain must contain a dot(.)")
	}
	return nil
}

// verifyUserPassword는 사용자의 패스워드를 확인하고 유효하지 않다면 에러를 낸다.
func verifyUserPassword(pw string) error {
	if len(pw) < 8 {
		return BadRequest("password is too short")
	}
	return nil
}

// AddUser는 db에 한 명의 사용자를 추가한다.
func AddUser(db *sql.DB, id, pw string) error {
	user, domain, err := splitUserID(id)
	if err != nil {
		return err
	}
	// 이 이름을 가진 사용자가 이미 있는지 검사한다.
	_, err = GetUser(db, id)
	if err == nil {
		return BadRequest("user already exists: %s", id)
	} else if !errors.As(err, &NotFoundError{}) {
		return err
	}
	// 로컬 사용자에 대해서만 비밀번호를 등록한다.
	//
	// OIDC 유저는 추후 별도의 내부 패스워드를 등록할 수 있고, 그랬을 때만 OIDC를 통하지 않고
	// 로그인 할 수 있다. 물론 이는 권장되지는 않지만 OIDC 제공자의 사이트에 문제가 생기거나
	// 인터넷이 갑자기 막혔을 때 우회하는 방법으로 사용될 수 있다.
	hashed_password := ""
	if domain == "" {
		// 로컬 사용자
		hashed, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		hashed_password = string(hashed)
	}
	// 사용자 생성
	u := &userInfo{User: user, Domain: domain, HashedPassword: hashed_password}
	stmts := []dbStatement{
		dbStmt(fmt.Sprintf("INSERT INTO users (%s) VALUES (%s)", userdbkey, userdbidx), dbVals(u)...),
	}
	return dbExec(db, stmts)
}

func Users(db *sql.DB) ([]*User, error) {
	stmt := dbStmt(fmt.Sprintf("SELECT %s FROM users", userDBKey))
	us := make([]*User, 0)
	err := dbQuery(db, stmt, func(rows *sql.Rows) error {
		u := &User{}
		err := scan(rows, u)
		if err != nil {
			return err
		}
		us = append(us, u)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return us, nil
}

// GetUser는 db에서 사용자를 검색한다.
// 해당 유저를 찾지 못하면 nil과 NotFound 에러를 반환한다.
func GetUser(db *sql.DB, id string) (*User, error) {
	user, domain, err := splitUserID(id)
	if err != nil {
		return nil, err
	}
	stmt := dbStmt(fmt.Sprintf("SELECT %s FROM users WHERE username='%s' AND domain='%s'", userDBKey, user, domain))
	u := &User{}
	err = dbQueryRow(db, stmt, func(row *sql.Row) error {
		return scan(row, u)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NotFound("user not found: %s", id)
		}
		return nil, err
	}
	return u, err
}

// UserPasswordMatch는 db에 저장된 사용자의 비밀번호와 입력된 비밀번호가 같은지를 비교한다.
// 해당 사용자가 없거나, 불러오는데 에러가 나면 false와 에러를 반환한다.
func UserPasswordMatch(db *sql.DB, id, pw string) (bool, error) {
	user, domain, err := splitUserID(id)
	if err != nil {
		return false, err
	}
	stmt := dbStmt(fmt.Sprintf("SELECT hashed_password FROM users WHERE username='%s' AND domain='%s'", user, domain))
	var hashed_password string
	err = dbQueryRow(db, stmt, func(row *sql.Row) error {
		return row.Scan(&hashed_password)
	})
	// OIDC 사용자가 패스워드를 따로 설정하지 않았다면, 오직 OIDC를 통해서만 로그인 할 수 있다.
	if domain != "" && hashed_password == "" {
		return false, BadRequest("OIDC user who didn't set local password could not login via password")
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, NotFound("user not found: %s", user)
		}
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashed_password), []byte(pw))
	if err != nil {
		return false, nil
	}
	return true, nil
}

// UpdateUser는 db에 비밀번호를 제외한 유저 필드를 업데이트 한다.
// 이 함수를 호출하기 전 해당 유저가 존재하는지를 사용자가 검사해야한다.
func UpdateUser(db *sql.DB, id string, u *User) error {
	if u == nil {
		return fmt.Errorf("nil user")
	}
	user, domain, err := splitUserID(id)
	if err != nil {
		return err
	}
	stmts := []dbStatement{
		dbStmt(fmt.Sprintf("UPDATE users SET (%s) = (%s) WHERE username='%s' AND domain='%s'", userDBKey, userDBIdx, user, domain), dbVals(u)...),
	}
	return dbExec(db, stmts)
}

type UserConfig struct {
	CurrentShow string `db:"current_show"`
}

var userConfigDBKey string = strings.Join(dbKeys(&UserConfig{}), ", ")
var userConfigDBIdx string = strings.Join(dbIdxs(&UserConfig{}), ", ")
var _ []interface{} = dbVals(&UserConfig{})

// UpdateUserConfig는 유저의 설정 값들을 받아온다.
func GetUserConfig(db *sql.DB, id string) (*UserConfig, error) {
	user, domain, err := splitUserID(id)
	if err != nil {
		return nil, err
	}
	stmt := dbStmt(fmt.Sprintf("SELECT %s FROM users WHERE username='%s' AND domain='%s'", userConfigDBKey, user, domain))
	u := &UserConfig{}
	err = dbQueryRow(db, stmt, func(row *sql.Row) error {
		return scan(row, u)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, NotFound("user not found: %s", id)
		}
		return nil, err
	}
	return u, nil
}

// UpdateUserConfig는 유저의 설정 값들을 업데이트 한다.
func UpdateUserConfig(db *sql.DB, id string, u *UserConfig) error {
	if u == nil {
		return BadRequest("user config shold not nil")
	}
	user, domain, err := splitUserID(id)
	if err != nil {
		return err
	}
	stmts := []dbStatement{
		dbStmt(fmt.Sprintf("UPDATE users SET (%s) = (%s) WHERE username='%s' AND domain='%s'", userConfigDBKey, userConfigDBIdx, user, domain), dbVals(u)...),
	}
	return dbExec(db, stmts)
}

// UpdateUserPassword는 db에 저장된 사용자 패스워드를 수정한다.
func UpdateUserPassword(db *sql.DB, id, pw string) error {
	user, domain, err := splitUserID(id)
	if err != nil {
		return err
	}
	err = verifyUserPassword(pw)
	if err != nil {
		return err
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("could not generate hash from password: %v", err)
	}
	hashed_password := string(hashed)
	stmts := []dbStatement{
		dbStmt(fmt.Sprintf("UPDATE users SET hashed_password=$1 WHERE username='%s' AND domain='%s'", user, domain), hashed_password),
	}
	return dbExec(db, stmts)
}

// DeleteUser는 해당 id의 사용자를 지운다.
// 만일 해당 아이디의 사용자가 없다면 에러를 낸다.
func DeleteUser(db *sql.DB, id string) error {
	user, domain, err := splitUserID(id)
	if err != nil {
		return err
	}
	_, err = GetUser(db, id)
	if err != nil {
		return err
	}
	stmts := []dbStatement{
		dbStmt(fmt.Sprintf("DELETE FROM users WHERE username='%s' AND domain='%s'", user, domain)),
	}
	return dbExec(db, stmts)
}
