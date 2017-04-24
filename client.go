/* Copyright 2016-2017 Vector Creations Ltd
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

package gomatrixserverlib

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// A Client makes request to the federation listeners of matrix
// homeservers
type Client struct {
	client http.Client
}

// UserInfo represents information about a user.
type UserInfo struct {
	Sub string `json:"sub"`
}

// NewClient makes a new Client
func NewClient() *Client {
	// TODO: Verify ceritificates
	tripper := federationTripper{
		transport: &http.Transport{
			// Set our own DialTLS function to avoid the default net/http SNI.
			// By default net/http and crypto/tls set the SNI to the target host.
			// By avoiding the default implementation we can keep the ServerName
			// as the empty string so that crypto/tls doesn't add SNI.
			DialTLS: func(network, addr string) (net.Conn, error) {
				rawconn, err := net.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				// Wrap a raw connection ourselves since tls.Dial defaults the SNI
				conn := tls.Client(rawconn, &tls.Config{
					ServerName: "",
					// TODO: We should be checking that the TLS certificate we see here matches
					//       one of the allowed SHA-256 fingerprints for the server.
					InsecureSkipVerify: true,
				})
				if err := conn.Handshake(); err != nil {
					return nil, err
				}
				return conn, nil
			},
		},
	}

	return &Client{
		client: http.Client{Transport: &tripper},
	}
}

type federationTripper struct {
	transport http.RoundTripper
}

func makeHTTPSURL(u *url.URL, addr string) (httpsURL url.URL) {
	httpsURL = *u
	httpsURL.Scheme = "https"
	httpsURL.Host = addr
	return
}

func (f *federationTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	host := r.URL.Host
	dnsResult, err := LookupServer(host)
	if err != nil {
		return nil, err
	}
	var resp *http.Response
	for _, addr := range dnsResult.Addrs {
		u := makeHTTPSURL(r.URL, addr)
		r.URL = &u
		resp, err = f.transport.RoundTrip(r)
		if err == nil {
			return resp, nil
		}
	}
	return nil, fmt.Errorf("no address found for matrix host %v", host)
}

// LookupUserInfo gets information about a user from a given matrix homeserver
// using a bearer access token.
func (fc *Client) LookupUserInfo(matrixServer, token string) (u UserInfo, err error) {
	url := url.URL{
		Scheme:   "matrix",
		Host:     matrixServer,
		Path:     "/_matrix/federation/v1/openid/userinfo",
		RawQuery: url.Values{"access_token": []string{token}}.Encode(),
	}

	var response *http.Response
	response, err = fc.client.Get(url.String())
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var errorOutput []byte
		errorOutput, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return
		}
		err = fmt.Errorf("HTTP %d : %s", response.StatusCode, errorOutput)
		return
	}

	err = json.NewDecoder(response.Body).Decode(&u)
	if err != nil {
		return
	}

	userParts := strings.SplitN(u.Sub, ":", 2)
	if len(userParts) != 2 || userParts[1] != matrixServer {
		err = fmt.Errorf("userID doesn't match server name '%v' != '%v'", u.Sub, matrixServer)
		return
	}

	return
}

// ServerKeys lookups up the keys for a matrix server from a matrix server.
// Returns the keys or a error if there was a problem talking to
func (fc *Client) ServerKeys(
	matrixServer string, keyRequests map[PublicKeyRequest]Timestamp,
) (map[PublicKeyRequest]ServerKeys, error) {
	url := url.URL{
		Scheme: "matrix",
		Host:   matrixServer,
		Path:   "/_matrix/key/v2/query",
	}

	// The request format is:
	// { "server_keys": { "<server_name>": { "<key_id>": { "minimum_valid_until_ts": <ts> }}}
	type keyreq struct {
		MinimumValidUntilTS Timestamp `json:"minimum_valid_until_ts"`
	}
	request := struct {
		ServerKeys map[string]map[string]keyreq `json:"server_keys"`
	}{map[string]map[string]keyreq{}}
	for k, ts := range keyRequests {
		server := request.ServerKeys[k.ServerName]
		if server == nil {
			server = map[string]keyreq{}
			request.ServerKeys[k.ServerName] = server
		}
		server[k.KeyID] = keyreq{ts}
	}

	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	response, err := fc.client.Post(url.String(), "application/json", bytes.NewBuffer(requestBytes))
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 {
		var errorOutput []byte
		if errorOutput, err = ioutil.ReadAll(response.Body); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("HTTP %d : %s", response.StatusCode, errorOutput)
	}

	var body struct {
		ServerKeys []ServerKeys `json:"server_keys"`
	}
	if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, err
	}

	result := map[PublicKeyRequest]ServerKeys{}
	for _, keys := range body.ServerKeys {
		for keyID := range keys.VerifyKeys {
			result[PublicKeyRequest{keys.ServerName, keyID}] = keys
		}
		for keyID := range keys.OldVerifyKeys {
			result[PublicKeyRequest{keys.ServerName, keyID}] = keys
		}
	}
	return result, nil
}
