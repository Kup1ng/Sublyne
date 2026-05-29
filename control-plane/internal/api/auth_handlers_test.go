package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/auth"
)

// httpResult is what tests inspect: status, body bytes, response
// headers, and any cookies the server set. The helpers below close
// the body before returning so the bodyclose linter is satisfied
// without leaking the *http.Response into test code.
type httpResult struct {
	Status  int
	Body    []byte
	Headers http.Header
	Cookies []*http.Cookie
}

// panelURL prepends the test web prefix to path so handler tests don't
// have to think about the obfuscation prefix on every call.
func panelURL(s *httptest.Server, path string) string {
	return s.URL + "/" + testWebPath + path
}

func httpServerForFixture(t *testing.T, f *testFixture) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(NewRouter(f.routerDeps()))
	t.Cleanup(s.Close)
	return s
}

func doRequest(t *testing.T, req *http.Request) httpResult {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return httpResult{
		Status:  resp.StatusCode,
		Body:    body,
		Headers: resp.Header.Clone(),
		Cookies: resp.Cookies(),
	}
}

func postJSON(t *testing.T, url, body string, headers map[string]string) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doRequest(t, req)
}

func getJSON(t *testing.T, url string, headers map[string]string) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doRequest(t, req)
}

func sessionCookie(r httpResult) *http.Cookie {
	for _, c := range r.Cookies {
		if c.Name == SessionCookieName {
			return c
		}
	}
	return nil
}

func TestLogin_Success(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)

	r := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", r.Status, string(r.Body))
	}

	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(r.Body, &out); err != nil {
		t.Fatalf("decode response: %v body=%s", err, string(r.Body))
	}
	if out.Token == "" {
		t.Fatal("token missing in response body")
	}
	cookie := sessionCookie(r)
	if cookie == nil {
		t.Fatal("session cookie was not set")
	}
	if !cookie.HttpOnly {
		t.Error("cookie should be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie SameSite = %v, want Strict", cookie.SameSite)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)

	r := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"wrong"}`, nil)
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", r.Status)
	}
	if c := sessionCookie(r); c != nil && c.Value != "" {
		t.Error("cookie should not be set on failed login")
	}
}

func TestLogin_WrongUsername(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := postJSON(t, panelURL(s, "/api/login"), `{"username":"other","password":"correct horse"}`, nil)
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", r.Status)
	}
}

func TestLogin_LockoutAfterFiveFailures(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)

	for i := 0; i < auth.DefaultLockoutThreshold; i++ {
		r := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"wrong"}`, nil)
		if r.Status != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i, r.Status)
		}
	}
	// Sixth attempt with the CORRECT password should still be locked out.
	r := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if r.Status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", r.Status)
	}
	if r.Headers.Get("Retry-After") == "" {
		t.Error("Retry-After header missing on 429")
	}
}

func TestLogin_LockoutExpires(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	for i := 0; i < auth.DefaultLockoutThreshold; i++ {
		_ = postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"wrong"}`, nil)
	}
	// Advance past the failure window so failures fall out and the
	// IP can attempt again.
	f.advance(auth.DefaultLockoutWindow + auth.DefaultLockoutDuration + time.Second)
	r := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("status after lockout expiry = %d (%s), want 200", r.Status, string(r.Body))
	}
}

func TestProtectedRoute_RequiresToken(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := getJSON(t, panelURL(s, "/api/session"), nil)
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", r.Status)
	}
}

func TestProtectedRoute_AcceptsBearer(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	login := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if login.Status != http.StatusOK {
		t.Fatalf("login status = %d", login.Status)
	}
	var creds struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(login.Body, &creds); err != nil {
		t.Fatal(err)
	}
	r := getJSON(t, panelURL(s, "/api/session"), map[string]string{"Authorization": "Bearer " + creds.Token})
	if r.Status != http.StatusOK {
		t.Fatalf("session status = %d (%s), want 200", r.Status, string(r.Body))
	}
	var sess struct {
		Username   string `json:"username"`
		ServerRole string `json:"server_role"`
	}
	if err := json.Unmarshal(r.Body, &sess); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if sess.Username != "admin" || sess.ServerRole != "client" {
		t.Errorf("session = %+v, want admin/client", sess)
	}
}

func TestProtectedRoute_AcceptsCookie(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	login := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	cookie := sessionCookie(login)
	if cookie == nil {
		t.Fatal("no session cookie returned")
	}
	req, err := http.NewRequest(http.MethodGet, panelURL(s, "/api/session"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	r := doRequest(t, req)
	if r.Status != http.StatusOK {
		t.Fatalf("session via cookie status = %d, want 200", r.Status)
	}
}

func TestProtectedRoute_RejectsTamperedBearer(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	login := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if login.Status != http.StatusOK {
		t.Fatalf("login status = %d", login.Status)
	}
	var creds struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(login.Body, &creds); err != nil {
		t.Fatal(err)
	}
	tampered := creds.Token + "X"
	r := getJSON(t, panelURL(s, "/api/session"), map[string]string{"Authorization": "Bearer " + tampered})
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", r.Status)
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := postJSON(t, panelURL(s, "/api/logout"), `{}`, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("logout status = %d", r.Status)
	}
	cleared := false
	for _, c := range r.Cookies {
		if c.Name == SessionCookieName && (c.MaxAge < 0 || c.Value == "") {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear sublyne_token cookie")
	}
}

func TestPasswordChange_Success(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	login := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if login.Status != http.StatusOK {
		t.Fatalf("login: %d %s", login.Status, string(login.Body))
	}
	var creds struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(login.Body, &creds); err != nil {
		t.Fatal(err)
	}
	change := postJSON(t, panelURL(s, "/api/password"),
		`{"current_password":"correct horse","new_password":"new strong pw"}`,
		map[string]string{"Authorization": "Bearer " + creds.Token})
	if change.Status != http.StatusOK {
		t.Fatalf("password change status = %d (%s), want 200", change.Status, string(change.Body))
	}
	// Old password no longer logs in.
	old := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if old.Status != http.StatusUnauthorized {
		t.Errorf("old password still works: status = %d", old.Status)
	}
	// New password logs in.
	fresh := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"new strong pw"}`, nil)
	if fresh.Status != http.StatusOK {
		t.Errorf("new password rejected: status = %d", fresh.Status)
	}
}

func TestPasswordChange_RequiresCurrentPassword(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	login := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if login.Status != http.StatusOK {
		t.Fatalf("login: %d %s", login.Status, string(login.Body))
	}
	var creds struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(login.Body, &creds); err != nil {
		t.Fatal(err)
	}
	r := postJSON(t, panelURL(s, "/api/password"),
		`{"current_password":"wrong","new_password":"new strong pw"}`,
		map[string]string{"Authorization": "Bearer " + creds.Token})
	if r.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", r.Status)
	}
}

func TestPasswordChange_RequiresAuth(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := postJSON(t, panelURL(s, "/api/password"),
		`{"current_password":"correct horse","new_password":"new strong pw"}`, nil)
	if r.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", r.Status)
	}
}

func TestPasswordChange_RejectsShortPassword(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	login := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if login.Status != http.StatusOK {
		t.Fatalf("login: %d %s", login.Status, string(login.Body))
	}
	var creds struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(login.Body, &creds); err != nil {
		t.Fatal(err)
	}
	r := postJSON(t, panelURL(s, "/api/password"),
		`{"current_password":"correct horse","new_password":"short"}`,
		map[string]string{"Authorization": "Bearer " + creds.Token})
	if r.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", r.Status)
	}
}

func TestHealthz_OK(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := getJSON(t, panelURL(s, "/healthz"), nil)
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	if string(r.Body) != "ok" {
		t.Errorf("body = %q, want ok", string(r.Body))
	}
}

func TestHealthz_AlsoUnderAPI(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := getJSON(t, panelURL(s, "/api/healthz"), nil)
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	if string(r.Body) != "ok" {
		t.Errorf("body = %q, want ok", string(r.Body))
	}
}
