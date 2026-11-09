package update

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func preserveUpdateLock(t *testing.T) {
	t.Helper()
	previous := lock
	t.Cleanup(func() { lock = previous })
}

func waitForUpdate(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("update handler did not finish")
	}
}

func startUpdate(h *Handler, request *http.Request) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Handle(httptest.NewRecorder(), request)
	}()
	return done
}

func TestHandleImageQueries(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		want        []string
	}{
		{"all images", "", nil},
		{"unrelated parameter", "?other=value", nil},
		{"single", "?image=app:latest", []string{"app:latest"}},
		{"comma separated and repeated", "?image=app,db&image=cache&image=app", []string{"app", "db", "cache", "app"}},
		{"URL decoded", "?image=registry%2Fapp%3Atag%2Cdb&image=space+name", []string{"registry/app:tag", "db", "space name"}},
		{"empty image", "?image=", []string{""}},
		{"empty elements retained", "?image=,app,&image=", []string{"", "app", "", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			preserveUpdateLock(t)
			calls := 0
			var got []string
			h := New(func(images []string) { calls++; got = images }, nil)
			if h.Path != "/v1/update" {
				t.Fatalf("handler path = %q", h.Path)
			}
			h.Handle(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, h.Path+tc.query, nil))
			if calls != 1 || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("calls/images = %d/%#v, want 1/%#v", calls, got, tc.want)
			}
			select {
			case token := <-lock:
				if !token {
					t.Error("default lock token = false, want true")
				}
			default:
				t.Fatal("lock token was not released")
			}
		})
	}
}

// This reader signals that the request has reached body consumption, without data.
type signalingBody struct{ read chan struct{} }

func (b signalingBody) Read([]byte) (int, error) { close(b.read); return 0, io.EOF }
func (b signalingBody) Close() error             { return nil }

func TestHandleImageRequestUsesInjectedLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		preserveUpdateLock(t)
		injected := make(chan bool, 1)
		called := make(chan struct{})
		h := New(func([]string) {
			select {
			case <-injected:
				t.Error("callback ran without acquiring the injected lock")
			default:
			}
			close(called)
		}, injected)
		bodyRead := make(chan struct{})
		request := httptest.NewRequest(http.MethodPost, h.Path+"?image=app", nil)
		request.Body = signalingBody{read: bodyRead}
		done := startUpdate(h, request)
		t.Cleanup(func() {
			select {
			case injected <- false:
			default:
			}
			waitForUpdate(t, done)
		})
		waitForUpdate(t, bodyRead)
		// Let the handler reach the empty lock before asserting it is waiting.
		synctest.Wait()
		select {
		case <-called:
			t.Fatal("image-specific request did not wait for the lock")
		default:
		}
		injected <- false
		waitForUpdate(t, done)
		select {
		case <-called:
		default:
			t.Fatal("callback was not invoked")
		}
		select {
		case token := <-injected:
			if token {
				t.Fatal("handler did not preserve the injected false token")
			}
		default:
			t.Fatal("injected lock was not released")
		}
	})
}

func TestHandleSkipsConcurrentAllImageScan(t *testing.T) {
	preserveUpdateLock(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var calls atomic.Int32
	h := New(func(images []string) {
		if images != nil {
			t.Errorf("all-image callback received %#v", images)
		}
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
	}, nil)
	first := startUpdate(h, httptest.NewRequest(http.MethodPost, h.Path, nil))
	requests := []<-chan struct{}{first}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		for _, done := range requests {
			waitForUpdate(t, done)
		}
	})
	waitForUpdate(t, entered)
	second := startUpdate(h, httptest.NewRequest(http.MethodPost, h.Path, nil))
	requests = append(requests, second)
	waitForUpdate(t, second)
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent scan invoked callback: calls = %d", got)
	}
	releaseOnce.Do(func() { close(release) })
	waitForUpdate(t, first)
	third := startUpdate(h, httptest.NewRequest(http.MethodPost, h.Path, nil))
	requests = append(requests, third)
	waitForUpdate(t, third)
	if got := calls.Load(); got != 2 {
		t.Fatalf("scan after release: calls = %d, want 2", got)
	}
}

func TestHandleReleasesLockWhenCallbackPanics(t *testing.T) {
	for _, query := range []string{"", "?image=app"} {
		t.Run(query, func(t *testing.T) {
			preserveUpdateLock(t)
			injected := make(chan bool, 1)
			injected <- false
			const panicValue = "callback failed"
			h := New(func([]string) { panic(panicValue) }, injected)
			func() {
				defer func() {
					if got := recover(); got != panicValue {
						t.Errorf("panic = %v, want %q", got, panicValue)
					}
				}()
				h.Handle(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, h.Path+query, nil))
			}()
			select {
			case token := <-injected:
				if token {
					t.Error("lock token was changed")
				}
			default:
				t.Fatal("lock leaked after callback panic")
			}
		})
	}
}

type failingBody struct{ err error }

func (b failingBody) Read([]byte) (int, error) { return 0, b.err }
func (b failingBody) Close() error             { return nil }

func TestHandleBodyReadFailureSuppressesCallback(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		available   bool
	}{
		{"all images with free lock", "", true},
		{"specific image with free lock", "?image=app", true},
		{"all images with busy lock", "", false},
		{"specific image with busy lock", "?image=app", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			preserveUpdateLock(t)
			injected := make(chan bool, 1)
			if tc.available {
				injected <- false
			}
			var calls atomic.Int32
			h := New(func([]string) { calls.Add(1) }, injected)
			request := httptest.NewRequest(http.MethodPost, h.Path+tc.query, nil)
			request.Body = failingBody{err: errors.New("request body read failed")}
			done := startUpdate(h, request)
			t.Cleanup(func() {
				select {
				case injected <- false:
				default:
				}
				waitForUpdate(t, done)
			})
			waitForUpdate(t, done)
			if got := calls.Load(); got != 0 {
				t.Fatalf("callback ran after body-read failure: %d calls", got)
			}
			select {
			case token := <-injected:
				if !tc.available || token {
					t.Error("body-read failure changed lock state")
				}
			default:
				if tc.available {
					t.Fatal("body-read failure consumed lock token")
				}
			}
		})
	}
}
