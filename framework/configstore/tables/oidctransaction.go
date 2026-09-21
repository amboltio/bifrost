package tables

import (
	"fmt"
	"strings"
	"time"

	"github.com/maximhq/bifrost/framework/encrypt"
	"gorm.io/gorm"
)

// TableOIDCTransaction is the durable, short-lived correlation record for an
// interactive dashboard OIDC login. State and nonce are stored only as
// digests, while the PKCE verifier is encrypted at rest when config-store
// encryption is enabled. Provider tokens and raw ID-token claims are never
// persisted here.
type TableOIDCTransaction struct {
	ID               string     `gorm:"primaryKey;type:varchar(255)" json:"id"`
	StateHash        string     `gorm:"type:char(64);not null;uniqueIndex:idx_identity_oidc_transactions_state_hash" json:"-"`
	NonceHash        string     `gorm:"type:char(64);not null" json:"-"`
	ProviderID       string     `gorm:"type:varchar(255);not null;index" json:"provider_id"`
	CodeVerifier     string     `gorm:"type:text;not null" json:"-"`
	RedirectPath     string     `gorm:"type:text;not null" json:"-"`
	ExpiresAt        time.Time  `gorm:"not null;index" json:"expires_at"`
	ConsumedAt       *time.Time `gorm:"index" json:"consumed_at,omitempty"`
	EncryptionStatus string     `gorm:"type:varchar(20);default:'plain_text'" json:"-"`
	CreatedAt        time.Time  `gorm:"index;not null" json:"created_at"`
	UpdatedAt        time.Time  `gorm:"index;not null" json:"updated_at"`
}

func (TableOIDCTransaction) TableName() string { return "identity_oidc_transactions" }

// BeforeCreate validates the callback correlation values before persistence.
// The state and nonce use one-way digests so a database disclosure cannot be
// used to forge a callback or satisfy an ID-token nonce check.
func (t *TableOIDCTransaction) BeforeCreate(*gorm.DB) error {
	t.StateHash = strings.TrimSpace(t.StateHash)
	t.NonceHash = strings.TrimSpace(t.NonceHash)
	t.ProviderID = strings.TrimSpace(t.ProviderID)
	t.RedirectPath = strings.TrimSpace(t.RedirectPath)
	if t.StateHash == "" || t.NonceHash == "" || t.ProviderID == "" || t.CodeVerifier == "" || t.RedirectPath == "" || t.ExpiresAt.IsZero() {
		return fmt.Errorf("OIDC transaction requires state hash, nonce hash, provider ID, PKCE verifier, redirect path, and expiry")
	}
	return nil
}

// BeforeSave encrypts the only callback secret retained by the transaction.
// Map updates used to consume a state carry no verifier and therefore do not
// trigger this hook's encryption branch. The status guard also keeps an
// already encrypted row from being encrypted a second time during a save.
func (t *TableOIDCTransaction) BeforeSave(*gorm.DB) error {
	if encrypt.IsEnabled() && t.CodeVerifier != "" && t.EncryptionStatus != EncryptionStatusEncrypted {
		if err := encryptString(&t.CodeVerifier); err != nil {
			return fmt.Errorf("encrypt OIDC transaction PKCE verifier: %w", err)
		}
		t.EncryptionStatus = EncryptionStatusEncrypted
	}
	return nil
}

func (t *TableOIDCTransaction) AfterFind(*gorm.DB) error {
	if t.EncryptionStatus != EncryptionStatusEncrypted || t.CodeVerifier == "" {
		return nil
	}
	if err := decryptString(&t.CodeVerifier); err != nil {
		return fmt.Errorf("decrypt OIDC transaction PKCE verifier: %w", err)
	}
	return nil
}
