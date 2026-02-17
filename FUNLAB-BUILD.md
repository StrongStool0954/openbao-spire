# OpenBao with SPIRE Seal - Funlab Custom Build

## Overview

This is a custom build of OpenBao v2.0.0 with integrated SPIRE seal support for the Funlab.casa infrastructure.

## Features

### SPIRE Seal Plugin

Hybrid attestation-based auto-unseal combining:
- **SPIRE** for workload identity and attestation
- **PKCS11** for hardware-backed key storage (TPM or YubiKey)
- **Runtime monitoring** with automatic seal on attestation failure

### Architecture

```
OpenBao SPIRE Seal
├─ SPIRE Workload API (attestation)
│  └─ Checks SVID validity before crypto operations
├─ PKCS11 Backend (key storage)
│  ├─ TPM 2.0 via tpm2_pkcs11
│  └─ YubiKey via ykcs11
└─ Runtime Monitor
   ├─ SVID refresh every 30 seconds
   ├─ Auto-seal after 3 consecutive failures
   └─ Integrated with Keylime attestation

```

### Attestation Chain

```
Boot: Keylime Agent → SPIRE Agent → OpenBao Unseals
Runtime: Keylime Failure → SPIRE SVID Denied → OpenBao Seals
```

## Build Information

- **Base Version**: OpenBao v2.0.0-HEAD (commit 906e336)
- **Custom Tag**: v2.0.0-funlab-spire.1
- **Build Date**: 2026-02-16T18:31:36Z
- **Go Version**: 1.25.7
- **CGO**: Enabled
- **Build Tags**: hsm

## Building

```bash
export PATH=$PATH:/usr/local/go/bin
cd openbao
CGO_ENABLED=1 BUILD_TAGS="hsm" make dev
```

## Configuration

### TPM Backend (Phase 1)

```hcl
seal "spire" {
  socket_path    = "/run/spire/sockets/agent.sock"
  trust_domain   = "funlab.casa"
  
  pkcs11_lib     = "/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so.1"
  pkcs11_slot    = "1"
  pkcs11_pin     = "openbaopin"
  pkcs11_token   = "openbao"
  key_label      = "openbao-unseal-key"
  hmac_key_label = "openbao-unseal-hmac"
}
```

### YubiKey Backend (Phase 2)

```hcl
seal "spire" {
  socket_path    = "/run/spire/sockets/agent.sock"
  trust_domain   = "funlab.casa"
  
  pkcs11_lib     = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
  pkcs11_slot    = "0"
  pkcs11_pin     = "123456"
  key_label      = "openbao-unseal-key"
  hmac_key_label = "openbao-unseal-hmac"
}
```

## Installation

### Prerequisites

- TPM 2.0 hardware or YubiKey
- SPIRE agent running with Keylime attestation
- tpm2-tools, libtpm2-pkcs11 (for TPM)
- ykcs11 (for YubiKey)

### Install Binary

```bash
sudo cp bin/bao /usr/bin/
sudo chown root:root /usr/bin/bao
sudo chmod 755 /usr/bin/bao
```

### Systemd Service Updates

```bash
# Allow TPM access
sudo tee /etc/systemd/system/openbao.service.d/tpm-access.conf > /dev/null << "SVCEOF"
[Service]
PrivateDevices=no
SVCEOF

# Set PKCS11 store path
sudo tee /etc/systemd/system/openbao.service.d/tpm-pkcs11.conf > /dev/null << "SVCEOF"
[Service]
Environment="TPM2_PKCS11_STORE=/var/lib/tpm2-pkcs11"
SVCEOF

sudo systemctl daemon-reload
```

## Testing

### Verify Seal Type

```bash
curl -sk https://openbao.funlab.casa:8088/v1/sys/seal-status | jq .type
# Should return: "spire"
```

### Check SPIRE Integration

```bash
sudo journalctl -u openbao.service | grep -i "spire"
# Should show: SPIRE Socket, SPIRE Trust Domain
```

### Reboot Test

```bash
sudo systemctl reboot
# After reboot:
curl -sk https://openbao.funlab.casa:8088/v1/sys/seal-status
# Should show: "sealed": false (auto-unsealed)
```

## Files Modified

- `vault/seal/spire/spire.go` - SPIRE seal implementation
- `vault/seal/spire/no_spire.go` - Stub for non-HSM builds
- `helper/configutil/kms.go` - SPIRE seal registration
- `go.mod` - Added go-spiffe dependency

## Authors

- Funlab Admin <admin@funlab.casa>
- Claude Sonnet 4.5 <noreply@anthropic.com>

## License

MPL-2.0 (same as OpenBao)
