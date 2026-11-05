package setup

import (
	"context"
	_ "embed"

	"github.com/zitadel/zitadel/internal/database"
	"github.com/zitadel/zitadel/internal/eventstore"
)

// Spalk: numbered apart from upstream's steps so a rebase never collides with theirs.

var (
	//go:embed spalk_01.sql
	addOIDCIsEmailVerified string
)

type IDPTemplate6OIDCIsEmailVerified struct {
	dbClient *database.DB
}

func (mig *IDPTemplate6OIDCIsEmailVerified) Execute(ctx context.Context, _ eventstore.Event) error {
	_, err := mig.dbClient.ExecContext(ctx, addOIDCIsEmailVerified)
	return err
}

func (mig *IDPTemplate6OIDCIsEmailVerified) String() string {
	return "spalk_01_idp_templates6_oidc_add_is_email_verified"
}
