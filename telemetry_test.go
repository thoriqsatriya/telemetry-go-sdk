/*
 * Copyright 2019 AccelByte Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/AccelByte/iam-go-sdk"
	"github.com/stretchr/testify/assert"
)

// newBytesReadCloser wraps a byte buffer with implementations so it'll
// satisfy the io.ReadCloser interface.
func newBytesReadCloser(buf []byte) *bytesReadCloser {
	return &bytesReadCloser{bytes.NewReader(buf)}
}

// bytesReadCloser wraps io.ReadSeeker useful for making a byte buffer
// acts like a io.ReadCloser.
type bytesReadCloser struct {
	body io.ReadSeeker
}

// Read satisfies io.Reader interface
func (readCloser *bytesReadCloser) Read(p []byte) (readLen int, err error) {
	readLen, err = readCloser.body.Read(p)
	if err == io.EOF {
		return 0, err
	}
	return readLen, err
}

// Close satisfies io.Closer interface
func (readCloser *bytesReadCloser) Close() error {
	return nil
}

type mockHTTPClient struct {
	mockDo  func(r *http.Request) (*http.Response, error)
	counter int
	data    interface{}
}

func (client *mockHTTPClient) Do(request *http.Request) (*http.Response, error) {
	client.counter++
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	client.data = body
	return client.mockDo(request)
}

// IAMClient is the mock of IAM client
type IAMClient struct {
	clientToken func() string
}

func (iamClient *IAMClient) ClientTokenGrant() error {
	return nil
}

func (iamClient *IAMClient) ClientToken() string {
	return ""
}

func (iamClient *IAMClient) StartLocalValidation() error {
	return nil
}

func (iamClient *IAMClient) ValidateAccessToken(accessToken string) (bool, error) {
	return true, nil
}

func (iamClient *IAMClient) ValidateAndParseClaims(accessToken string) (*iam.JWTClaims, error) {
	return &iam.JWTClaims{}, nil
}

func (iamClient *IAMClient) ValidatePermission(claims *iam.JWTClaims, requiredPermission iam.Permission,
	permissionResources map[string]string) (bool, error) {
	return true, nil
}

func (iamClient *IAMClient) ValidateRole(requiredRoleID string, claims *iam.JWTClaims) (bool, error) {
	return true, nil
}

func (iamClient *IAMClient) UserPhoneVerificationStatus(claims *iam.JWTClaims) (bool, error) {
	return true, nil
}

func (iamClient *IAMClient) UserEmailVerificationStatus(claims *iam.JWTClaims) (bool, error) {
	return true, nil
}

func (iamClient *IAMClient) UserAnonymousStatus(claims *iam.JWTClaims) (bool, error) {
	return true, nil
}

func (iamClient *IAMClient) HasBan(claims *iam.JWTClaims, banType string) bool {
	return true
}

func (iamClient *IAMClient) HealthCheck() bool {
	return true
}

func TestCalculateRestfulMetricsValidData(t *testing.T) {
	tests := []struct {
		rawData   []RestfulMetricsData
		aggregate *RestfulAggregateData
	}{
		{
			[]RestfulMetricsData{
				{
					ResponseTime: 100 * time.Millisecond,
					URLPath:      "GET/test",
					ResponseCode: http.StatusOK,
				},
				{
					ResponseTime: 200 * time.Millisecond,
					URLPath:      "GET/test",
					ResponseCode: http.StatusOK,
				},
				{
					ResponseTime: 300 * time.Millisecond,
					URLPath:      "GET/test",
					ResponseCode: http.StatusOK,
				},
			},
			&RestfulAggregateData{
				RequestCount:        map[string]int{"GET/test": 3},
				AverageResponseTime: map[string]int{"GET/test": 200},
				ResponseCodeCount:   map[int]int{200: 3},
			},
		},
		{
			[]RestfulMetricsData{
				{
					ResponseTime: 100 * time.Millisecond,
					URLPath:      "GET/test",
					ResponseCode: http.StatusOK,
				},
				{
					ResponseTime: 200 * time.Millisecond,
					URLPath:      "GET/test2",
					ResponseCode: http.StatusOK,
				},
				{
					ResponseTime: 300 * time.Millisecond,
					URLPath:      "GET/test3",
					ResponseCode: http.StatusOK,
				},
			},
			&RestfulAggregateData{
				RequestCount:        map[string]int{"GET/test": 1, "GET/test2": 1, "GET/test3": 1},
				AverageResponseTime: map[string]int{"GET/test": 100, "GET/test2": 200, "GET/test3": 300},
				ResponseCodeCount:   map[int]int{200: 3},
			},
		},
		{
			[]RestfulMetricsData{
				{
					ResponseTime: 100 * time.Millisecond,
					URLPath:      "GET/test",
					ResponseCode: http.StatusOK,
				},
				{
					ResponseTime: 200 * time.Millisecond,
					URLPath:      "GET/test2",
					ResponseCode: http.StatusOK,
				},
				{
					ResponseTime: 300 * time.Millisecond,
					URLPath:      "GET/test3",
					ResponseCode: http.StatusOK,
				},
			},
			&RestfulAggregateData{
				RequestCount:        map[string]int{"GET/test": 1, "GET/test2": 1, "GET/test3": 1},
				AverageResponseTime: map[string]int{"GET/test": 100, "GET/test2": 200, "GET/test3": 300},
				ResponseCodeCount:   map[int]int{200: 3},
			},
		},
		{
			[]RestfulMetricsData{
				{
					ResponseTime: 100 * time.Millisecond,
					URLPath:      "GET/test",
					ResponseCode: http.StatusBadRequest,
				},
				{
					ResponseTime: 200 * time.Millisecond,
					URLPath:      "GET/test",
					ResponseCode: http.StatusUnauthorized,
				},
				{
					ResponseTime: 300 * time.Millisecond,
					URLPath:      "GET/test",
					ResponseCode: http.StatusForbidden,
				},
			},
			&RestfulAggregateData{
				RequestCount:        map[string]int{"GET/test": 3},
				AverageResponseTime: map[string]int{"GET/test": 200},
				ResponseCodeCount:   map[int]int{400: 1, 401: 1, 403: 1},
			},
		},
	}

	for _, test := range tests {
		client := Client{
			restfulMetricsQueue: test.rawData,
		}
		aggregate, err := client.calculateRestfulMetrics()

		assert.Equal(t, test.aggregate, aggregate, "the result is not equal")
		assert.Nil(t, err, "nil should be nil")
	}
}

func TestCalculateRestfulMetricsEmptyPath(t *testing.T) {
	rawData := []RestfulMetricsData{
		{
			ResponseTime: 100 * time.Millisecond,
			URLPath:      "",
			ResponseCode: http.StatusOK,
		},
	}

	expectedResult := &RestfulAggregateData{
		RequestCount:        map[string]int{"": 1},
		AverageResponseTime: map[string]int{"": 100},
		ResponseCodeCount:   map[int]int{200: 1},
	}

	client := Client{
		restfulMetricsQueue: rawData,
	}
	aggregate, err := client.calculateRestfulMetrics()

	assert.Equal(t, expectedResult, aggregate, "the result is not equal")
	assert.Nil(t, err, "nil should be nil")
}

func TestCalculateRestfulMetricsNoData(t *testing.T) {
	client := Client{}
	aggregate, err := client.calculateRestfulMetrics()

	assert.Nil(t, aggregate, "aggregate should be nil")
	assert.Nil(t, err, "nil should be nil")
}

func TestSendingDataSuccessful(t *testing.T) {
	httpClient := &mockHTTPClient{
		mockDo: func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       newBytesReadCloser([]byte("body")),
			}, nil
		},
	}

	iamMock := &IAMClient{
		clientToken: func() string {
			return "clientToken"
		},
	}

	client := &Client{
		httpClientFunc: func() HTTPClient {
			return httpClient
		},
		iamClient: iamMock,
	}

	event := client.constructEvent("testData")
	err := client.sendData(event)

	assert.Equal(t, 1, httpClient.counter, "http counter is not equal")
	assert.NoError(t, err, "error should be nil")
}

func TestSendingDataUnauthorized(t *testing.T) {
	httpClient := &mockHTTPClient{
		mockDo: func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Body:       newBytesReadCloser([]byte("body")),
			}, nil
		},
	}

	iamMock := &IAMClient{
		clientToken: func() string {
			return "clientToken"
		},
	}

	client := &Client{
		httpClientFunc: func() HTTPClient {
			return httpClient
		},
		iamClient: iamMock,
	}

	event := client.constructEvent("testData")
	err := client.sendData(event)

	assert.Equal(t, 1, httpClient.counter, "http counter is not equal")
	assert.Error(t, err, "should be error")
}

func TestSendingDataError(t *testing.T) {
	httpClient := &mockHTTPClient{
		mockDo: func(r *http.Request) (*http.Response, error) {
			return &http.Response{}, fmt.Errorf("simulate error")
		},
	}

	iamMock := &IAMClient{
		clientToken: func() string {
			return "clientToken"
		},
	}

	client := &Client{
		httpClientFunc: func() HTTPClient {
			return httpClient
		},
		iamClient: iamMock,
	}

	event := client.constructEvent("testData")
	err := client.sendData(event)

	assert.Equal(t, 1, httpClient.counter, "http counter is not equal")
	assert.Error(t, err, "should be error")
}

func TestSendingDataNoData(t *testing.T) {
	client := &Client{}
	err := client.sendData(nil)

	assert.Error(t, err, "should be error")
}

func TestNewClient(t *testing.T) {
	dataChan := make(chan interface{})
	stopChan := make(chan bool)

	client := NewClient("telemetryURL", "testRealm", time.Second, dataChan, stopChan, nil, "clientID")

	assert.Equal(t, "telemetryURL", client.telemetryURL)
	assert.Equal(t, "testRealm", client.realm)
	assert.Equal(t, "clientID", client.clientID)
	assert.Nil(t, client.iamClient)
	assert.Equal(t, dataChan, client.dataChan)
	assert.Equal(t, stopChan, client.stopChan)
}

func TestNewClientWithCustomHttpFunc(t *testing.T) {
	dataChan := make(chan interface{})
	stopChan := make(chan bool)

	httpFunc := func() HTTPClient {
		return &http.Client{}
	}

	client := NewClient("telemetryURL", "testRealm", time.Second, dataChan, stopChan, nil, "clientID").WithHTTPClientFunc(httpFunc)

	assert.Equal(t, "telemetryURL", client.telemetryURL)
	assert.Equal(t, "testRealm", client.realm)
	assert.Equal(t, "clientID", client.clientID)
	assert.Nil(t, client.iamClient)
	assert.Equal(t, dataChan, client.dataChan)
	assert.Equal(t, stopChan, client.stopChan)
}

func TestProcessDataSuccessful(t *testing.T) {
	httpClient := &mockHTTPClient{
		mockDo: func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       newBytesReadCloser([]byte("body")),
			}, nil
		},
	}
	httpFunc := func() HTTPClient {
		return httpClient
	}

	iamMock := &IAMClient{
		clientToken: func() string {
			return "clientToken"
		},
	}

	dataChan := make(chan interface{})
	stopChan := make(chan bool)

	client := NewClient("telemetryURL", "testRealm", time.Millisecond, dataChan, stopChan, iamMock, "clientID").WithHTTPClientFunc(httpFunc)

	go func(client *Client) {
		client.processData()
	}(client)

	client.StoreRestfulMetrics(&RestfulMetricsData{
		ResponseTime: 100 * time.Millisecond,
		URLPath:      "GET/test",
		ResponseCode: http.StatusOK})
	client.StoreRestfulMetrics(&RestfulMetricsData{
		ResponseTime: 150 * time.Millisecond,
		URLPath:      "GET/test",
		ResponseCode: http.StatusOK})
	client.StoreRestfulMetrics(&RestfulMetricsData{
		ResponseTime: 200 * time.Millisecond,
		URLPath:      "GET/test",
		ResponseCode: http.StatusOK})

	time.Sleep(time.Millisecond * 10)
	client.Stop()

	var data Event

	err := json.Unmarshal(httpClient.data.([]byte), &data)

	fmt.Println(data.Data)

	expectedData := map[string]interface{}{
		"AverageResponseTime": map[string]interface{}{"GET/test": 150},
		"RequestCount":        map[string]interface{}{"GET/test": 3},
		"ResponseCodeCount":   map[string]interface{}{"200": 3},
	}

	assert.Equal(t, expectedData, data.Data)

	assert.NoError(t, err, "error should be nil")
	assert.Equal(t, 1, httpClient.counter, "http counter is not equal")
}
