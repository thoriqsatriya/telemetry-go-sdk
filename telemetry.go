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
	"net/http"
	"strings"
	"time"

	"github.com/AccelByte/iam-go-sdk"
	"github.com/montanaflynn/stats"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	backendAgentType         = 300
	telemetryEventType       = 66
	telemetrySendDataEventID = 15000
)

// Event holds the outer telemetry event structure
type Event struct {
	EventID    int32       `json:"EventID"`
	EventType  int32       `json:"EventType"`
	EventLevel int32       `json:"EventLevel"`
	UX         int8        `json:"UX"`
	AgentType  int16       `json:"AgentType"`
	EventTime  time.Time   `json:"EventTime"`
	ClientID   string      `json:"ClientID,omitempty"`
	UUID       string      `json:"UUID"`
	Data       interface{} `json:"Data"`
}

// RestfulMetricsData holds data for restful metrics data
type RestfulMetricsData struct {
	URLPath      string
	ResponseTime time.Duration
	ResponseCode int
}

// RestfulAggregateData holds data for restful aggregate metrics
type RestfulAggregateData struct {
	AverageResponseTime map[string]int `json:"AverageResponseTime"`
	RequestCount        map[string]int `json:"RequestCount"`
	ResponseCodeCount   map[int]int    `json:"ResponseCodeCount"`
}

// Client holds the telemetry client
type Client struct {
	ticker              *time.Ticker
	telemetryURL        string
	realm               string
	clientID            string
	dataChan            chan interface{}
	stopChan            chan bool
	restfulMetricsQueue []RestfulMetricsData
	iamClient           iam.Client
	httpClientFunc      func() HTTPClient
}

// NewClient creates new telemetry client
func NewClient(telemetryURL string, realm string, sendInterval time.Duration, dataChan chan interface{},
	stopChan chan bool, iamClient iam.Client, clientID string) *Client {
	ticker := time.NewTicker(sendInterval)

	return &Client{
		ticker:       ticker,
		telemetryURL: telemetryURL,
		realm:        realm,
		dataChan:     dataChan,
		stopChan:     stopChan,
		iamClient:    iamClient,
		clientID:     clientID,
		httpClientFunc: func() HTTPClient {
			return &http.Client{}
		},
	}
}

// HTTPClient is interface which could be fulfilled by http.Client
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// WithHTTPClientFunc allows custom http clients
func (client *Client) WithHTTPClientFunc(fn func() HTTPClient) *Client {
	client.httpClientFunc = fn
	return client
}

// Start starts the main process of data collecting and sending. It begins the ticker
func (client *Client) Start() {
	go client.processData()
}

// Stop stops the process
func (client *Client) Stop() {
	client.stopChan <- true
}

// StoreRestfulMetrics stores restful metrics data locally and temporarily to be calculated when sending data
func (client *Client) StoreRestfulMetrics(event *RestfulMetricsData) {
	client.dataChan <- event
}

// processData calculate temporal metrics, send the results to telemetry, and flush the local storage
func (client *Client) processData() {
	for {
		select {
		case <-client.ticker.C:
			aggregate, err := client.calculateRestfulMetrics()
			if err != nil {
				logrus.Error("error calculate restful metrics: ", err)
				continue
			}
			if aggregate == nil {
				logrus.Info("no metrics data stored")
				continue
			}
			event := client.constructEvent(aggregate)
			err = client.sendData(event)
			if err != nil {
				logrus.Error("unable to send data: ", err)
			}

		case metrics := <-client.dataChan:
			switch event := metrics.(type) {
			case *RestfulMetricsData:
				client.restfulMetricsQueue = append(client.restfulMetricsQueue, *event)
			}

		case <-client.stopChan:
			aggregate, err := client.calculateRestfulMetrics()
			if err != nil {
				logrus.Error("error calculate restful metrics: ", err)
				return
			}
			if aggregate == nil {
				logrus.Info("no metrics data stored")
				return
			}
			event := client.constructEvent(aggregate)
			err = client.sendData(event)
			if err != nil {
				logrus.Error("unable to send data: ", err)
			}
			return
		}
	}
}

func (client *Client) calculateRestfulMetrics() (aggregate *RestfulAggregateData, err error) {
	if len(client.restfulMetricsQueue) == 0 {
		return nil, nil
	}

	responseCodeCountMap := make(map[int]int)
	requestCount := make(map[string]int)
	responseTimeAggregate := make(map[string][]float64)

	for _, metric := range client.restfulMetricsQueue {
		responseCodeCountMap[metric.ResponseCode]++
		requestCount[metric.URLPath]++
		responseTimeAggregate[metric.URLPath] =
			append(responseTimeAggregate[metric.URLPath], float64(metric.ResponseTime/time.Millisecond))
	}

	averageResponseTime := make(map[string]int)
	var respTime float64
	for key, value := range responseTimeAggregate {
		respTime, err = stats.Mean(value)
		if err != nil {
			return nil, err
		}
		averageResponseTime[key] = int(respTime)
	}

	aggregate = &RestfulAggregateData{
		AverageResponseTime: averageResponseTime,
		RequestCount:        requestCount,
		ResponseCodeCount:   responseCodeCountMap,
	}

	client.restfulMetricsQueue = make([]RestfulMetricsData, 0)

	return aggregate, err
}

func (client *Client) constructEvent(data interface{}) *Event {
	id, err := uuid.NewV4()
	if err != nil {
		return nil
	}

	// todo: fix the constant
	return &Event{
		Data:       data,
		EventTime:  time.Now().UTC(),
		UUID:       strings.Replace(id.String(), "-", "", -1),
		AgentType:  backendAgentType,
		EventType:  telemetryEventType,
		EventLevel: 3,
		UX:         1,
		EventID:    telemetrySendDataEventID,
		ClientID:   client.clientID,
	}
}

func (client *Client) sendData(event *Event) error {
	if event == nil {
		return fmt.Errorf("event can't be nil")
	}
	eventByte, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// todo: fix url
	url := fmt.Sprintf("%s/public/events/backendservice/%d/%d/%d", client.telemetryURL, event.EventType,
		event.EventLevel, event.EventID)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(eventByte))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	if client.iamClient != nil {
		req.Header.Add("Authorization", "Bearer "+client.iamClient.ClientToken())
	}

	res, err := client.httpClientFunc().Do(req)
	if err != nil {
		return err
	}

	defer func(r *http.Response) {
		e := r.Body.Close()
		if e != nil {
			return
		}
	}(res)

	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("telemetry returned non OK status: %v", res.StatusCode)
	}
	return nil
}
