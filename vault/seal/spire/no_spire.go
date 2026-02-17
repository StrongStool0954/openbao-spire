//go:build !hsm

// Copyright (c) 2026 OpenBao
// SPDX-License-Identifier: MPL-2.0

package spire

import (
	"context"
	"fmt"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const (
	WrapperTypeSPIRE = wrapping.WrapperType("spire")
)

type Wrapper struct{}

func NewWrapper() *Wrapper {
	return &Wrapper{}
}

func (w *Wrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	return nil, fmt.Errorf("SPIRE seal requires HSM support - build with 'hsm' tag")
}

func (w *Wrapper) Init(ctx context.Context, options ...wrapping.Option) error {
	return fmt.Errorf("SPIRE seal requires HSM support - build with 'hsm' tag")
}

func (w *Wrapper) Finalize(ctx context.Context, options ...wrapping.Option) error {
	return nil
}

func (w *Wrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
	return WrapperTypeSPIRE, nil
}

func (w *Wrapper) KeyId(ctx context.Context) (string, error) {
	return "", fmt.Errorf("SPIRE seal requires HSM support")
}

func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	return nil, fmt.Errorf("SPIRE seal requires HSM support")
}

func (w *Wrapper) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	return nil, fmt.Errorf("SPIRE seal requires HSM support")
}
