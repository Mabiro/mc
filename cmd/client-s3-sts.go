/*
 * Minio Client (C) 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/minio/minio-go/pkg/credentials"
)

// SAMLProvider -
type SAMLProvider struct {
	credentials.Expiry

	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// So a ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	ExpiryWindow time.Duration

	endpoint      string
	samlAssertion string
}

// Retrieve - retrieve new credentials.
func (m *SAMLProvider) Retrieve() (credentials.Value, error) {
	samlCreds, err := requestCred(m.samlAssertion, m.endpoint)
	if err != nil {
		return credentials.Value{}, err
	}

	m.SetExpiration(samlCreds.Expiration, m.ExpiryWindow)

	return credentials.Value{
		AccessKeyID:     samlCreds.AccessKey,
		SecretAccessKey: samlCreds.SecretKey,
	}, nil
}

// STS API version.
const stsAPIVersion = "2011-06-15"

type credential struct {
	AccessKey  string `xml:"AccessKeyId,omitempty"`
	SecretKey  string `xml:"SecretAccessKey,omitempty"`
	Expiration time.Time
}

// AssumeRoleWithSAMLResult - Contains the response to a successful AssumeRoleWithSAML request,
// including temporary AWS credentials that can be used to make AWS requests.
// Please also see https://docs.aws.amazon.com/goto/WebAPI/sts-2011-06-15/AssumeRoleWithSAMLResponse
type AssumeRoleWithSAMLResult struct {
	// The temporary security credentials, which include an access key ID, a secret
	// access key, and an expiration.
	Credentials credential `xml:",omitempty"`
}

func requestCred(samlAssertion string, endpoint string) (credential, error) {
	resp, err := http.PostForm(endpoint, url.Values{
		"Version":       {stsAPIVersion},
		"SAMLAssertion": {samlAssertion},
		// "PrincipalArn": "",
		// "RoleArn": "",
		// "DurationSeconds": "",
	})
	if err != nil {
		return credential{}, err
	}
	credXMLBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return credential{}, err
	}
	resp.Body.Close()

	var samlResult AssumeRoleWithSAMLResult
	if err = xml.Unmarshal(credXMLBytes, &samlResult); err != nil {
		return credential{}, err
	}

	return samlResult.Credentials, nil
}
