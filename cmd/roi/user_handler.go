package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/studio2l/roi"
)

func oidcCallbackHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	session, err := getSession(r)
	if err != nil {
		clearSession(w)
		return err
	}
	if r.FormValue("state") != session["state"] {
		// 현재 가지고 있는 state가 round-trip을 통해 돌아온 state와 다르다면
		// 중간에 요청이 변조된 것이다.
		return roi.BadRequest("states are not matching")
	}
	// code는 서버가 인증 토큰을 받기 위해 사용자에게 전달된 코드로,
	// 이를 이용해서 백엔드 채널로 안전하게 토큰을 획득한다.
	code := r.FormValue("code")
	if code == "" {
		return roi.BadRequest("no code in oauth response")
	}
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"code":          {code},
		"client_id":     {env.oidcClientID},
		"client_secret": {env.oidcClientSecret},
		"redirect_uri":  {env.oidcRedirectURI},
		"grant_type":    {"authorization_code"},
	})
	if err != nil {
		return err
	}
	oa := OAuth2Response{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&oa)
	if err != nil {
		return err
	}
	part := strings.Split(oa.IDToken, ".")
	if len(part) != 3 {
		return fmt.Errorf("oauth id token should consist of 3 parts")
	}
	// jwt 토큰은 그 서명을 검증해야 하나, 이 경우 인증 서버에서 직접 받았으므로 생략한다.
	payload, err := base64.RawURLEncoding.DecodeString(part[1])
	if err != nil {
		return err
	}
	op := OIDCPayload{}
	dec = json.NewDecoder(bytes.NewReader(payload))
	err = dec.Decode(&op)
	if err != nil {
		return err
	}
	// oidc 유저의 경우 id에 @이 항상 들어가므로 로컬유저와 구별된다.
	// 비밀번호는 필요하지 않다.
	id := op.Email // 구글 OIDC는 email 필드가 id 필드를 대신한다.
	_, err = roi.GetUser(DB, id)
	if err != nil {
		if !errors.As(err, &roi.NotFoundError{}) {
			return err
		}
		err := roi.AddUser(DB, id, "")
		if err != nil {
			return err
		}
	}
	session["userid"] = id
	err = setSession(w, session)
	if err != nil {
		return err
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return nil
}

type OAuth2Response struct {
	IDToken string `json:"id_token"`
}

type OIDCPayload struct {
	Email string `json:"email"`
}

// loginHandler는 /login 페이지로 사용자가 접속했을때 로그인 페이지를 반환한다.
func loginHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	if r.Method == "POST" {
		err := mustFields(r, "id", "password")
		if err != nil {
			return err
		}
		id := r.FormValue("id")
		pw := r.FormValue("password")
		match, err := roi.UserPasswordMatch(DB, id, pw)
		if err != nil {
			return err
		}
		if !match {
			return roi.BadRequest("entered password is not correct")
		}
		session := map[string]string{
			"userid": id,
		}
		err = setSession(w, session)
		if err != nil {
			return fmt.Errorf("could not set session: %w", err)
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	}

	if !env.useOIDC {
		return executeTemplate(w, "login", struct{ UseOIDC bool }{false})
	}

	// 사이트 간 요청위조를 방지하기 위해 state를 생성한다.
	seed := make([]byte, 1024)
	rand.Read(seed)
	h := sha256.New()
	h.Write(seed)
	state := fmt.Sprintf("%x", h.Sum(nil))

	session, err := getSession(r)
	if err != nil {
		clearSession(w)
		return err
	}
	session["state"] = state
	setSession(w, session)

	// 인증 서버에 대한 리플레이 공격을 방지하기 위한 nonce를 생성한다.
	seed = make([]byte, 1024)
	rand.Read(seed)
	h = sha256.New()
	h.Write(seed)
	nonce := fmt.Sprintf("%x", h.Sum(nil))

	recipe := struct {
		UseOIDC         bool
		OIDCClientID    string
		OIDCState       string
		OIDCRedirectURI string
		OIDCNonce       string
		OIDCHostDomain  string
	}{
		UseOIDC:         true,
		OIDCClientID:    env.oidcClientID,
		OIDCState:       state,
		OIDCRedirectURI: env.oidcRedirectURI,
		OIDCNonce:       nonce,
		OIDCHostDomain:  env.oidcHostDomain,
	}
	return executeTemplate(w, "login", recipe)
}

// logoutHandler는 /logout 페이지로 사용자가 접속했을때 사용자를 로그아웃 시킨다.
func logoutHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	clearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	return nil
}

// signupHandler는 /signup 페이지로 사용자가 접속했을때 가입 페이지를 반환한다.
func signupHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	if r.Method == "POST" {
		err := mustFields(r, "id", "password")
		if err != nil {
			return err
		}
		id := r.FormValue("id")
		pw := r.FormValue("password")
		// 할일: password에 대한 컨펌은 프론트 엔드에서 하여야 함
		pwc := r.FormValue("password_confirm")
		if pw != pwc {
			return roi.BadRequest("passwords are not matched")
		}
		err = roi.AddUser(DB, id, pw)
		if err != nil {
			return err
		}
		session := map[string]string{
			"userid": id,
		}
		err = setSession(w, session)
		if err != nil {
			return err
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return nil
	}
	return executeTemplate(w, "signup", nil)
}

// profileHandler는 /profile 페이지로 사용자가 접속했을 때 사용자 프로필 페이지를 반환한다.
func profileHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	if r.Method == "POST" {
		id := r.FormValue("id")
		if env.User.ID() != id {
			return roi.BadRequest("not allowed to change other's profile")
		}
		u, err := roi.GetUser(DB, id)
		if err != nil {
			return err
		}
		u.DisplayName = r.FormValue("display_name")
		u.Team = r.FormValue("team")
		u.Role = r.FormValue("position")
		u.Email = r.FormValue("email")
		u.PhoneNumber = r.FormValue("phone_number")
		u.EntryDate = r.FormValue("entry_date")

		err = roi.UpdateUser(DB, id, u)
		if err != nil {
			return err
		}
		http.Redirect(w, r, "/settings/profile", http.StatusSeeOther)
		return nil
	}
	recipe := struct {
		Env  *Env
		User *roi.User
	}{
		Env:  env,
		User: env.User,
	}
	return executeTemplate(w, "profile", recipe)
}

// updatePasswordHandler는 /update-password 페이지로 사용자가 패스워드 변경과 관련된 정보를 보내면
// 사용자 패스워드를 변경한다.
func updatePasswordHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	err := mustFields(r, "old_password", "new_password")
	if err != nil {
		return err
	}
	oldpw := r.FormValue("old_password")
	newpw := r.FormValue("new_password")
	if len(newpw) < 8 {
		return roi.BadRequest("new password too short")
	}
	// 할일: password에 대한 컨펌은 프론트 엔드에서 하여야 함
	newpwc := r.FormValue("new_password_confirm")
	if newpw != newpwc {
		return roi.BadRequest("passwords are not matched")
	}
	match, err := roi.UserPasswordMatch(DB, env.User.ID(), oldpw)
	if err != nil {
		return err
	}
	if !match {
		return roi.BadRequest("entered password is not correct")
	}
	err = roi.UpdateUserPassword(DB, env.User.ID(), newpw)
	if err != nil {
		return err
	}
	http.Redirect(w, r, "/settings/profile", http.StatusSeeOther)
	return nil
}

// userHandler는 루트 페이지로 사용자가 접근했을때 그 사용자에게 필요한 정보를 맞춤식으로 제공한다.
func userHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	id := r.URL.Path[len("/user/"):]
	u, err := roi.GetUser(DB, id)
	if err != nil {
		return err
	}
	tasks, err := roi.UserTasks(DB, id)
	if err != nil {
		return err
	}
	// 태스크를 미리 아이디 기준으로 정렬해 두면 아래에서 사용되는
	// tasksOfDay 또한 아이디 기준으로 정렬된다.
	sort.Slice(tasks, func(i, j int) bool {
		ti := tasks[i]
		tj := tasks[j]
		c := strings.Compare(ti.Show, tj.Show)
		if c < 0 {
			return true
		} else if c > 0 {
			return false
		}
		c = strings.Compare(ti.Group, tj.Group)
		if c < 0 {
			return true
		} else if c > 0 {
			return false
		}
		c = strings.Compare(ti.Unit, tj.Unit)
		if c < 0 {
			return true
		} else if c > 0 {
			return false
		}
		c = strings.Compare(ti.Task, tj.Task)
		if c <= 0 {
			return true
		}
		return false
	})
	taskFromID := make(map[string]*roi.Task)
	for _, t := range tasks {
		taskFromID[env.User.ID()] = t
	}
	tasksOfDay := make(map[string][]string, 28)
	for _, t := range tasks {
		due := stringFromDate(t.DueDate)
		if tasksOfDay[due] == nil {
			tasksOfDay[due] = make([]string, 0)
		}
		tasksOfDay[due] = append(tasksOfDay[due], env.User.ID())
	}
	// 앞으로 4주에 대한 태스크 정보를 보인다.
	// 총 기간이나 단위는 추후 설정할 수 있도록 할 것.
	timeline := make([]string, 28)
	y, m, d := time.Now().Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.Local)
	for i := range timeline {
		timeline[i] = stringFromDate(today.Add(time.Duration(i) * 24 * time.Hour))
	}
	numTasks := make(map[string]map[roi.Status]int)
	for _, t := range tasks {
		if numTasks[t.Show] == nil {
			numTasks[t.Show] = make(map[roi.Status]int)
		}
		numTasks[t.Show][t.Status] += 1
	}
	recipe := struct {
		Env           *Env
		User          *roi.User
		Timeline      []string
		NumTasks      map[string]map[roi.Status]int
		TaskFromID    map[string]*roi.Task
		TasksOfDay    map[string][]string
		AllTaskStatus []roi.Status
	}{
		Env:           env,
		User:          u,
		Timeline:      timeline,
		NumTasks:      numTasks,
		TaskFromID:    taskFromID,
		TasksOfDay:    tasksOfDay,
		AllTaskStatus: roi.AllTaskStatus,
	}
	return executeTemplate(w, "user", recipe)
}

func usersHandler(w http.ResponseWriter, r *http.Request, env *Env) error {
	us, err := roi.Users(DB)
	if err != nil {
		return err
	}
	recipe := struct {
		Env   *Env
		Users []*roi.User
	}{
		Env:   env,
		Users: us,
	}
	return executeTemplate(w, "users", recipe)
}
