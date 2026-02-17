//go:build hsm

// Copyright (c) 2026 OpenBao
// SPDX-License-Identifier: MPL-2.0

package spire

import (
	"context"
	"fmt"
	"sync"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	pkcs11 "github.com/openbao/go-kms-wrapping/wrappers/pkcs11/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	WrapperTypeSPIRE = wrapping.WrapperType("spire")
)

type Wrapper struct {
	spireClient   *workloadapi.Client
	socketPath    string
	trustDomain   string
	logger        hclog.Logger

	currentSVID   *x509svid.SVID
	svidMutex     sync.RWMutex

	pkcs11Wrapper wrapping.Wrapper

	ctx           context.Context
	cancel        context.CancelFunc
}

func NewWrapper() *Wrapper {
	return &Wrapper{}
}

func (w *Wrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}

	w.socketPath = getConfigValue(opts.WithConfigMap, "socket_path", "/run/spire/sockets/agent.sock")
	w.trustDomain = getConfigValue(opts.WithConfigMap, "trust_domain", "funlab.casa")
	
	pkcs11Lib := getConfigValue(opts.WithConfigMap, "pkcs11_lib", "")
	if pkcs11Lib == "" {
		return nil, fmt.Errorf("pkcs11_lib must be specified")
	}

	w.logger = hclog.NewNullLogger()

	return &wrapping.WrapperConfig{
		Metadata: map[string]string{
			"socket_path":   w.socketPath,
			"trust_domain":  w.trustDomain,
			"pkcs11_lib":    pkcs11Lib,
			"pkcs11_token":  getConfigValue(opts.WithConfigMap, "pkcs11_token", ""),
		},
	}, nil
}

func (w *Wrapper) Init(ctx context.Context, options ...wrapping.Option) error {
	w.logger.Info("initializing SPIRE seal", "socket_path", w.socketPath)

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+w.socketPath))
	if err != nil {
		return fmt.Errorf("failed to create SPIRE workload API client: %w", err)
	}
	w.spireClient = client

	if err := w.refreshSVID(ctx); err != nil {
		w.spireClient.Close()
		return fmt.Errorf("failed to fetch initial SVID (attestation failed): %w", err)
	}

	w.logger.Info("SPIRE attestation successful, initializing PKCS11 backend")

	opts, _ := wrapping.GetOpts(options...)

	pkcs11Config := make(map[string]string)
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			if len(k) > 7 && k[:7] == "pkcs11_" {
				pkcs11Config[k[7:]] = v
			}
		}
	}

	w.pkcs11Wrapper = pkcs11.NewWrapper()
	_, err = w.pkcs11Wrapper.SetConfig(ctx, wrapping.WithConfigMap(pkcs11Config))
	if err != nil {
		w.spireClient.Close()
		return fmt.Errorf("failed to configure PKCS11 backend: %w", err)
	}

	if initWrapper, ok := w.pkcs11Wrapper.(wrapping.InitFinalizer); ok {
		if err := initWrapper.Init(ctx); err != nil {
			w.spireClient.Close()
			return fmt.Errorf("failed to initialize PKCS11 backend: %w", err)
		}
	}

	w.ctx, w.cancel = context.WithCancel(context.Background())
	go w.monitorSVID()

	w.logger.Info("SPIRE seal initialized successfully")
	return nil
}

func (w *Wrapper) Finalize(ctx context.Context, options ...wrapping.Option) error {
	if w.cancel != nil {
		w.cancel()
	}
	if w.pkcs11Wrapper != nil {
		if finalizer, ok := w.pkcs11Wrapper.(wrapping.InitFinalizer); ok {
			finalizer.Finalize(ctx, options...)
		}
	}
	if w.spireClient != nil {
		w.spireClient.Close()
	}
	w.logger.Info("SPIRE seal finalized")
	return nil
}

func (w *Wrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
	return WrapperTypeSPIRE, nil
}

func (w *Wrapper) KeyId(ctx context.Context) (string, error) {
	if w.pkcs11Wrapper != nil {
		return w.pkcs11Wrapper.KeyId(ctx)
	}
	return "spire-pkcs11", nil
}

func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if err := w.checkSVIDValid(); err != nil {
		return nil, fmt.Errorf("SPIRE attestation check failed: %w", err)
	}

	if w.pkcs11Wrapper == nil {
		return nil, fmt.Errorf("PKCS11 backend not initialized")
	}

	return w.pkcs11Wrapper.Encrypt(ctx, plaintext, options...)
}

func (w *Wrapper) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	if err := w.checkSVIDValid(); err != nil {
		return nil, fmt.Errorf("SPIRE attestation check failed: %w", err)
	}

	if w.pkcs11Wrapper == nil {
		return nil, fmt.Errorf("PKCS11 backend not initialized")
	}

	return w.pkcs11Wrapper.Decrypt(ctx, blob, options...)
}

func (w *Wrapper) checkSVIDValid() error {
	w.svidMutex.RLock()
	svid := w.currentSVID
	w.svidMutex.RUnlock()

	if svid == nil {
		return fmt.Errorf("no SVID available")
	}

	now := time.Now()
	for _, cert := range svid.Certificates {
		if now.Before(cert.NotBefore) {
			return fmt.Errorf("SVID not yet valid")
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("SVID expired")
		}
	}

	return nil
}

func (w *Wrapper) refreshSVID(ctx context.Context) error {
	w.logger.Debug("fetching SVID from SPIRE")

	svid, err := w.spireClient.FetchX509SVID(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch SVID: %w", err)
	}

	w.svidMutex.Lock()
	w.currentSVID = svid
	w.svidMutex.Unlock()

	w.logger.Info("SVID refreshed successfully", 
		"expires_at", svid.Certificates[0].NotAfter,
		"spiffe_id", svid.ID.String())

	return nil
}

func (w *Wrapper) monitorSVID() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	consecutiveFailures := 0
	maxFailures := 3

	for {
		select {
		case <-w.ctx.Done():
			w.logger.Info("SVID monitoring stopped")
			return

		case <-ticker.C:
			if err := w.refreshSVID(w.ctx); err != nil {
				consecutiveFailures++
				w.logger.Error("failed to refresh SVID", 
					"error", err, 
					"failures", consecutiveFailures,
					"max_failures", maxFailures)

				if consecutiveFailures >= maxFailures {
					w.logger.Error("SVID refresh failed multiple times - ATTESTATION FAILURE DETECTED",
						"failures", consecutiveFailures,
						"action", "sealing")

					w.svidMutex.Lock()
					w.currentSVID = nil
					w.svidMutex.Unlock()

					return
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
}

func getConfigValue(configMap map[string]string, key, defaultValue string) string {
	if configMap != nil {
		if val, ok := configMap[key]; ok {
			return val
		}
	}
	return defaultValue
}
