// Deliberately insecure demo: a model download on Go's default client, which never times out.
package keys

import (
	"io"
	"net/http"
	"os"
)

func Download(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}
