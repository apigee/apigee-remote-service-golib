// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/apigee/apigee-remote-service-golib/util"
	"github.com/google/uuid"
)

const GCPManagedHost = "apigee.googleapis.com"

type uploader interface {
	workFunc(tenant, fileName string) util.WorkFunc
	write(records []Record, writer io.Writer) error
	isGzipped() bool
}

type saasUploader struct {
	client  *http.Client
	baseURL *url.URL
	now     func() time.Time
}

func (s *saasUploader) isGzipped() bool {
	return true
}

// format and write records
func (s *saasUploader) write(records []Record, writer io.Writer) error {
	enc := json.NewEncoder(writer)
	for _, record := range records {
		if err := enc.Encode(record); err != nil {
			return fmt.Errorf("json encode: %s", err)
		}
	}
	return nil
}

func (s *saasUploader) workFunc(tenant, fileName string) util.WorkFunc {
	return func(ctx context.Context) error {
		if ctx.Err() == nil {
			return s.upload(tenant, fileName)
		}

		log.Warnf("canceled upload of %s: %v", fileName, ctx.Err())
		err := os.Remove(fileName)
		if err != nil && !os.IsNotExist(err) {
			log.Warnf("unable to remove file %s: %v", fileName, err)
		}
		return nil
	}
}

// upload sends a file to SaaS UAP
func (s *saasUploader) upload(tenant, fileName string) error {

	file, err := os.Open(fileName)
	if err != nil {
		return err
	}

	fi, err := file.Stat()
	if err != nil {
		return err
	}

	log.Debugf("getting signed URL for %s", fileName)
	signedURL, err := s.signedURL(tenant, fileName)
	if err != nil {
		return fmt.Errorf("signedURL: %s", err)
	}
	req, err := http.NewRequest("PUT", signedURL, file)
	if err != nil {
		return fmt.Errorf("http.NewRequest: %s", err)
	}

	// needs a bare client because udca service account is not authorized for GCS
	client := http.DefaultClient
	if s.baseURL.Hostname() != GCPManagedHost {
		// additional headers for legacy saas
		req.Header.Set("Expect", "100-continue")
		req.Header.Set("Content-Type", "application/x-gzip")
		req.Header.Set("x-amz-server-side-encryption", "AES256")
		// switch the client back to the default for legacy saas
		client = s.client
	}
	req.ContentLength = fi.Size()

	log.Debugf("uploading %s to %s", fileName, signedURL)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("client.Do(): %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := ioutil.ReadAll(resp.Body) // get the response for debug purpose
		return fmt.Errorf("upload %s returned %s %s", fileName, resp.Status, string(data))
	}

	if err := os.Remove(fileName); err != nil {
		return fmt.Errorf("rm %s: %s", fileName, err)
	}

	return nil
}

func (s *saasUploader) orgEnvFromSubdir(subdir string) (string, string) {
	splits := strings.Split(subdir, "~")
	if len(splits) == 2 {
		return splits[0], splits[1]
	}
	return "", ""
}

// uploadDir gets a directory for where we should upload the file.
func (s *saasUploader) uploadDir() string {
	now := s.now()
	d := now.Format("2006-01-02")
	t := now.Format("15-04-00")
	return fmt.Sprintf(pathFmt, d, t)
}

// signedURL asks for a signed URL that can be used to upload gzip file
func (s *saasUploader) signedURL(subdir, fileName string) (string, error) {
	var req *http.Request
	var err error
	if s.baseURL.Hostname() == GCPManagedHost {
		req, err = s.gcpGetSignedURLHTTPRequest(subdir, fileName)
	} else {
		req, err = s.legacyGetSignedURLHTTPRequest(subdir, fileName)
	}
	if err != nil {
		return "", err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status (code %d) returned from %s: %s", resp.StatusCode, req.URL.String(), resp.Status)
	}

	var data struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("error decoding response: %s", err)
	}
	return data.URL, nil
}

// legacyGetSignedURLHTTPRequest returns a *http.Request based on the the legacy analytics path and parameters
func (s *saasUploader) legacyGetSignedURLHTTPRequest(subdir, fileName string) (*http.Request, error) {
	org, env := s.orgEnvFromSubdir(subdir)
	if org == "" || env == "" {
		return nil, fmt.Errorf("invalid subdir %s", subdir)
	}

	ur := *s.baseURL
	ur.Path = path.Join(ur.Path, fmt.Sprintf(analyticsPath, org, env))
	req, err := http.NewRequest("GET", ur.String(), nil)
	if err != nil {
		return nil, err
	}

	relPath := filepath.Join(s.uploadDir(), filepath.Base(fileName))

	q := req.URL.Query()
	q.Add("tenant", subdir)
	q.Add("relative_file_path", relPath)
	q.Add("file_content_type", "application/x-gzip")
	q.Add("encrypt", "true")
	req.URL.RawQuery = q.Encode()

	return req, nil
}

// gcpGetSignedURLHTTPRequest returns a *http.Request based on the UAP analytics path and parameters
func (s *saasUploader) gcpGetSignedURLHTTPRequest(subdir, fileName string) (*http.Request, error) {
	org, env := s.orgEnvFromSubdir(subdir)
	if org == "" || env == "" {
		return nil, fmt.Errorf("invalid subdir %s", subdir)
	}

	ur := *s.baseURL
	ur.Path = path.Join(ur.Path, fmt.Sprintf(uapAnalyticsPath, org, env))
	req, err := http.NewRequest("GET", ur.String(), nil)
	if err != nil {
		return nil, err
	}

	relPath := fmt.Sprintf(relativeFilePathFmt, time.Now().Unix(), org, env, uuid.New().String())

	q := req.URL.Query()
	q.Add("repo", repoName)
	q.Add("dataset", datasetType)
	q.Add("relative_file_path", relPath)
	req.URL.RawQuery = q.Encode()

	return req, nil
}
