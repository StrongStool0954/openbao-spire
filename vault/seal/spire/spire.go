//go:build hsm

// Copyright (c) 2026 OpenBao
// SPDX-License-Identifier: MPL-2.0

package spire

import (
	"context"
	"fmt"
	"os"
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

	currentSVID      *x509svid.SVID
	svidMutex        sync.RWMutex
	attestationLost  bool          // True when attestation fails and vault should seal
	attestationMutex sync.RWMutex

	pkcs11Wrapper wrapping.Wrapper
	configMap     map[string]string  // Store config for Init

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

	// Store the full config map for later use in Init
	if opts.WithConfigMap != nil {
		w.configMap = make(map[string]string)
		for k, v := range opts.WithConfigMap {
			w.configMap[k] = v
		}
	}

	w.socketPath = getConfigValue(opts.WithConfigMap, "socket_path", "/run/spire/sockets/agent.sock")
	w.trustDomain = getConfigValue(opts.WithConfigMap, "trust_domain", "funlab.casa")

	pkcs11Lib := getConfigValue(opts.WithConfigMap, "pkcs11_lib", "")
	if pkcs11Lib == "" {
		return nil, fmt.Errorf("pkcs11_lib must be specified")
	}

	// Create a console logger for debugging
	w.logger = hclog.New(&hclog.LoggerOptions{
		Name:   "spire-seal",
		Level:  hclog.Debug,
		Output: os.Stderr,
	})
	w.logger.Info("========== SPIRE SEAL SETCONFIG CALLED ==========", "socket_path", w.socketPath, "trust_domain", w.trustDomain)

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
	w.logger.Info("========== SPIRE SEAL INIT CALLED ==========", "socket_path", w.socketPath)

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+w.socketPath))
	if err != nil {
		w.logger.Error("FAILED to create SPIRE workload API client", "error", err, "socket_path", w.socketPath)
		return fmt.Errorf("failed to create SPIRE workload API client: %w", err)
	}
	w.spireClient = client
	w.logger.Info("SPIRE workload API client created successfully")

	if err := w.refreshSVID(ctx); err != nil {
		w.logger.Error("FAILED to fetch initial SVID", "error", err)
		w.spireClient.Close()
		return fmt.Errorf("failed to fetch initial SVID (attestation failed): %w", err)
	}

	w.logger.Info("========== SPIRE ATTESTATION SUCCESSFUL, INITIALIZING PKCS11 ==========")

	// Use stored config map instead of expecting options
	pkcs11Config := make(map[string]string)
	if w.configMap != nil {
		for k, v := range w.configMap {
			if len(k) > 7 && k[:7] == "pkcs11_" {
				// Strip pkcs11_ prefix
				pkcs11Config[k[7:]] = v
			} else if k == "key_label" || k == "hmac_key_label" {
				// Pass through key_label and hmac_key_label directly
				pkcs11Config[k] = v
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

// AttestationFailed returns true if attestation has been lost and the vault should seal for security
func (w *Wrapper) AttestationFailed() bool {
	w.attestationMutex.RLock()
	defer w.attestationMutex.RUnlock()
	return w.attestationLost
}

// AttestationRestored returns true if attestation was lost but has now been recovered
func (w *Wrapper) AttestationRestored() bool {
	w.attestationMutex.RLock()
	defer w.attestationMutex.RUnlock()

	w.svidMutex.RLock()
	hasSVID := w.currentSVID != nil
	w.svidMutex.RUnlock()

	// Attestation is restored if we previously lost it but now have a valid SVID
	return !w.attestationLost && hasSVID
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
	normalInterval := 30 * time.Second
	recoveryInterval := 60 * time.Second
	ticker := time.NewTicker(normalInterval)
	defer ticker.Stop()

	consecutiveFailures := 0
	maxFailures := 3
	inRecoveryMode := false

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
					"max_failures", maxFailures,
					"recovery_mode", inRecoveryMode)

				if consecutiveFailures >= maxFailures && !inRecoveryMode {
					w.logger.Error("ATTESTATION FAILURE - Keylime/SPIRE attestation lost",
						"failures", consecutiveFailures,
						"action", "signaling Core to seal vault for security")

					w.svidMutex.Lock()
					w.currentSVID = nil
					w.svidMutex.Unlock()

					// Set attestation lost flag - Core will seal the vault
					w.attestationMutex.Lock()
					w.attestationLost = true
					w.attestationMutex.Unlock()

					// Enter recovery mode - continue polling at slower interval
					inRecoveryMode = true
					ticker.Reset(recoveryInterval)
					w.logger.Info("entering SPIRE recovery mode - monitoring for attestation restoration",
						"check_interval", recoveryInterval)
				}
			} else {
				// Success!
				if inRecoveryMode {
					w.logger.Info("ATTESTATION RESTORED - SPIRE connection recovered",
						"action", "will attempt auto-unseal")

					// Clear attestation lost flag - Core will attempt auto-unseal
					w.attestationMutex.Lock()
					w.attestationLost = false
					w.attestationMutex.Unlock()

					inRecoveryMode = false
					ticker.Reset(normalInterval)
					w.logger.Info("resuming normal operation", "check_interval", normalInterval)
				}
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
