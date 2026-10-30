// Deliberately insecure demo: a model-serving admin endpoint with the Go mistakes the review flags.
package keys

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func Serve(db interface{ Query(string, ...any) error }) {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	_ = client
	http.HandleFunc("/models", func(w http.ResponseWriter, r *http.Request) {
		_ = db.Query(fmt.Sprintf("SELECT * FROM models WHERE owner = '%s'", r.URL.Query().Get("owner")))
		data, _ := os.ReadFile(filepath.Join("/models", r.URL.Query().Get("name")))
		_ = os.WriteFile("/tmp/last-model", data, 0777)
		_ = exec.Command("sh", "-c", "ls -la /models/"+r.URL.Query().Get("name")).Run()
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})
	_ = http.ListenAndServe(":8080", nil)
}
