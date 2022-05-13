/*
 * Copyright 2017-2022 Provide Technologies Inc.
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

package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	servicebus "github.com/Azure/azure-service-bus-go"
	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
)

const defaultServiceBusInboundQueueName = "baseline.inbound"
const defaultServiceBusOutboundQueueName = "baseline.outbound"
const defaultServiceBusContextTimeout = 10 * time.Second

const subscribeTickInterval = 500 * time.Millisecond
const subscribeSleepInterval = 250 * time.Millisecond

// Dynamics365Service for the D365 API
type Dynamics365Service struct {
	client api.Client
	mutex  sync.Mutex

	inboundQueueName  *string
	outboundQueueName *string

	ctx    context.Context
	cancel context.CancelFunc

	ns *servicebus.Namespace

	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
}

// InitDynamics365Service convenience method to initialize a default `sap.Dynamics365Service` (i.e., production) instance
func InitDynamics365Service(token *string) *Dynamics365Service {
	ns, err := initServiceBusNamespace()
	if err != nil {
		common.Log.Warningf("failed to initialize azure service bus namespace; %s", err.Error())
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultServiceBusContextTimeout)

	service := &Dynamics365Service{
		client: api.Client{
			Token: token,
		},
		mutex:             sync.Mutex{},
		inboundQueueName:  common.StringOrNil(defaultServiceBusInboundQueueName),
		outboundQueueName: common.StringOrNil(defaultServiceBusOutboundQueueName),
		ctx:               ctx,
		cancel:            cancel,
		ns:                ns,
	}

	go service.subscribe()
	return service
}

// Authenticate a user by email address and password, returning a newly-authorized X-CSRF-Token token
func (s *Dynamics365Service) Authenticate() error {
	return nil
}

// ConfigureProxy configures a new proxy instance in D365 for a given organization
func (s *Dynamics365Service) ConfigureProxy(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// TODO: use inbound queue to send system requests to D365

	return fmt.Errorf("not implemented")
}

// ListSchemas retrieves a list of available schemas
func (s *Dynamics365Service) ListSchemas(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// GetSchema retrieves a business object model by type
func (s *Dynamics365Service) GetSchema(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// CreateObject is a generic way to create a business object in the D365 environment
func (s *Dynamics365Service) CreateObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	q, err := s.ns.NewQueue(*s.inboundQueueName)
	if err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(params)

	err = q.Send(s.ctx, servicebus.NewMessage(payload))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// UpdateObject updates a business object
func (s *Dynamics365Service) UpdateObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	q, err := s.ns.NewQueue(*s.inboundQueueName)
	if err != nil {
		return err
	}

	payload, _ := json.Marshal(params)

	err = q.Send(s.ctx, servicebus.NewMessage(payload))
	if err != nil {
		return err
	}

	return nil
}

// UpdateObjectStatus updates the status of a business object
func (s *Dynamics365Service) UpdateObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// TODO

	return nil
}

// DeleteProxyConfiguration drops a proxy configuration for the given organization
func (s *Dynamics365Service) DeleteProxyConfiguration(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// HealthCheck checks the health of the D365 instance
func (s *Dynamics365Service) HealthCheck() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// ProxyHealthCheck
func (s *Dynamics365Service) ProxyHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

func initServiceBusNamespace() (*servicebus.Namespace, error) {
	var ns *servicebus.Namespace
	var err error

	connStr := os.Getenv("AZURE_SERVICE_BUS_CONNECTION_STRING")
	if connStr == "" {
		msg := "failed to parse AZURE_SERVICE_BUS_CONNECTION_STRING from environment"
		common.Log.Warning(msg)
		return nil, errors.New(msg)
	}

	ns, err = servicebus.NewNamespace(servicebus.NamespaceWithConnectionString(connStr))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize azure service bus namespace; %s", err.Error())
	}

	return ns, nil
}

func (s *Dynamics365Service) receive() error {
	q, err := s.ns.NewQueue(*s.outboundQueueName)
	if err != nil {
		return err
	}

	err = q.ReceiveOne(
		s.ctx,
		servicebus.HandlerFunc(func(ctx context.Context, message *servicebus.Message) error {
			common.Log.Debug(string(message.Data))
			return message.Complete(ctx)
		}),
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *Dynamics365Service) installSignalHandlers() chan os.Signal {
	common.Log.Tracef("installing subshell signal handlers")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	return sigs
}

func (s *Dynamics365Service) subscribe() {
	sigs := s.installSignalHandlers()
	s.shutdownCtx, s.cancelF = context.WithCancel(context.Background())

	timer := time.NewTicker(subscribeTickInterval)
	defer timer.Stop()

	for !s.shuttingDown() {
		select {
		case <-timer.C:
			err := s.receive()
			if err != nil {
				common.Log.Warningf("failed to receive from azure service bus queue in subscribe runloop; %s", err.Error())
			}
		case sig := <-sigs:
			fmt.Printf("received signal: %s", sig)
			s.shutdown()
		case <-s.shutdownCtx.Done():
			close(sigs)
		default:
			time.Sleep(subscribeSleepInterval)
		}
	}

	log.Printf("exiting tunnel runloop")
	s.cancelF()
}

func (s *Dynamics365Service) shutdown() {
	if atomic.AddUint32(&s.closing, 1) == 1 {
		common.Log.Tracef("shutting down")
		s.cancelF()
	}
}

func (s *Dynamics365Service) shuttingDown() bool {
	return (atomic.LoadUint32(&s.closing) > 0)
}
