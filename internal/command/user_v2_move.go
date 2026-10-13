package command

import (
	"context"

	"github.com/zitadel/logging"

	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/user"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// MoveUser moves a human user to another organization of the same instance,
// keeping their ID.
//
// The eventstore ties an aggregate to the organization of its first event, so
// the user is removed from their organization and added to the target one in a
// single push: the added event enforces the new resource owner, and the user's
// credentials, multi-factor and passwordless authenticators, identity provider
// links, metadata and state are replayed after it. As with removing a user,
// their authorizations and administrator roles are removed, and their sessions
// end. Their avatar, pending verification codes and the
// skipping of multi-factor initialization are not carried over.
func (c *Commands) MoveUser(ctx context.Context, userID, organizationID string, cascadingUserMemberships []*CascadingMembership, cascadingGrantIDs []string) (_ *domain.ObjectDetails, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() { span.EndWithError(err) }()

	if userID == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "COMMAND-mv0usr1d7q", "Errors.User.UserIDMissing")
	}
	if organizationID == "" {
		return nil, zerrors.ThrowInvalidArgument(nil, "COMMAND-mv0org9k2w", "Errors.Org.Invalid")
	}

	// Load with human and service account events, so a service account is
	// recognised and refused rather than reported as missing.
	existing, err := c.userRemoveWriteModel(ctx, userID, "")
	if err != nil {
		return nil, err
	}
	if !isUserStateExists(existing.UserState) {
		return nil, zerrors.ThrowNotFound(nil, "COMMAND-mv4nf8ux3e", "Errors.User.NotFound")
	}
	if existing.Name != "" {
		return nil, zerrors.ThrowPreconditionFailed(nil, "COMMAND-mv7sa2qk5r", "Errors.User.NotHuman")
	}
	currentOrganizationID := existing.ResourceOwner
	if currentOrganizationID == organizationID {
		return nil, zerrors.ThrowPreconditionFailed(nil, "COMMAND-mv1same6tz", "Errors.User.AlreadyInOrganization")
	}

	if err := c.checkPermissionDeleteUser(ctx, currentOrganizationID, userID); err != nil {
		return nil, err
	}
	if err := c.checkPermissionUpdateUser(ctx, organizationID, userID, false); err != nil {
		return nil, err
	}
	if err := c.checkOrgExists(ctx, organizationID); err != nil {
		return nil, err
	}

	human, err := c.UserHumanWriteModel(ctx, userID, currentOrganizationID, true, true, true, true, false, true, true)
	if err != nil {
		return nil, err
	}
	authenticators, err := c.humanAuthenticatorsToMove(ctx, userID, currentOrganizationID)
	if err != nil {
		return nil, err
	}

	ownerDeleteReady, err := c.isUniqueConstraintOwnerDeleteReady(ctx)
	if err != nil {
		return nil, err
	}
	removeEvent, err := c.moveUserRemoveEvent(ctx, human, ownerDeleteReady)
	if err != nil {
		return nil, err
	}
	events := []eventstore.Command{removeEvent}

	for _, grantID := range cascadingGrantIDs {
		removeGrantEvent, _, err := c.removeUserGrant(ctx, grantID, "", true, true, nil)
		if err != nil {
			logging.WithFields("usergrantid", grantID).WithError(err).Warn("could not cascade remove role on user grant")
			continue
		}
		skipCascadeUniqueConstraints(ownerDeleteReady, removeGrantEvent)
		events = append(events, removeGrantEvent)
	}
	if len(cascadingUserMemberships) > 0 {
		membershipEvents, err := c.removeUserMemberships(ctx, cascadingUserMemberships)
		if err != nil {
			return nil, err
		}
		skipCascadeUniqueConstraints(ownerDeleteReady, membershipEvents...)
		events = append(events, membershipEvents...)
	}

	addEvents, err := c.moveUserAddEvents(ctx, human, authenticators, organizationID)
	if err != nil {
		return nil, err
	}
	events = append(events, addEvents...)

	pushedEvents, err := c.eventstore.Push(ctx, events...)
	if err != nil {
		return nil, err
	}
	moved := NewUserHumanWriteModel(userID, organizationID, false, false, false, false, false, false, false)
	if err := AppendAndReduce(moved, pushedEvents...); err != nil {
		return nil, err
	}
	return writeModelToObjectDetails(&moved.WriteModel), nil
}

// movedAuthenticators are the user's authenticators that are set up and so
// move with them.
type movedAuthenticators struct {
	totp          *HumanTOTPWriteModel
	otpSMS        bool
	otpEmail      bool
	u2f           []*domain.WebAuthNToken
	passwordless  []*domain.WebAuthNToken
	recoveryCodes []string
}

func (c *Commands) humanAuthenticatorsToMove(ctx context.Context, userID, organizationID string) (*movedAuthenticators, error) {
	totp := NewHumanTOTPWriteModel(userID, organizationID)
	otpSMS := NewHumanOTPSMSWriteModel(userID, organizationID)
	otpEmail := NewHumanOTPEmailWriteModel(userID, organizationID)
	recoveryCodes := NewHumanRecoveryCodeWriteModel(userID, organizationID)
	for _, wm := range []eventstore.QueryReducer{totp, otpSMS, otpEmail, recoveryCodes} {
		if err := c.eventstore.FilterToQueryReducer(ctx, wm); err != nil {
			return nil, err
		}
	}
	u2f, err := c.getHumanU2FTokens(ctx, userID, organizationID)
	if err != nil {
		return nil, err
	}
	passwordless, err := c.getHumanPasswordlessTokens(ctx, userID, organizationID)
	if err != nil {
		return nil, err
	}

	moved := &movedAuthenticators{
		otpSMS:       otpSMS.OTPAdded(),
		otpEmail:     otpEmail.OTPAdded(),
		u2f:          readyWebAuthNTokens(u2f),
		passwordless: readyWebAuthNTokens(passwordless),
	}
	if totp.State == domain.MFAStateReady {
		moved.totp = totp
	}
	if recoveryCodes.State == domain.MFAStateReady {
		moved.recoveryCodes = recoveryCodes.Codes()
	}
	return moved, nil
}

func readyWebAuthNTokens(tokens []*domain.WebAuthNToken) []*domain.WebAuthNToken {
	ready := make([]*domain.WebAuthNToken, 0, len(tokens))
	for _, token := range tokens {
		if token.State == domain.MFAStateReady {
			ready = append(ready, token)
		}
	}
	return ready
}

// moveUserRemoveEvent removes the user from their current organization. It
// enforces that organization as its resource owner, since the eventstore would
// otherwise give every event of the push the owner of the last enforcing event:
// the target organization.
func (c *Commands) moveUserRemoveEvent(ctx context.Context, human *UserV2WriteModel, ownerDeleteReady bool) (eventstore.Command, error) {
	aggregate := &human.Aggregate().Aggregate
	if ownerDeleteReady {
		return &userRemovedFromOrganizationEvent{user.NewUserRemovedByOwnerEvent(ctx, aggregate)}, nil
	}
	domainPolicy, err := c.domainPolicyWriteModel(ctx, human.ResourceOwner)
	if err != nil {
		return nil, zerrors.ThrowPreconditionFailed(err, "COMMAND-mv3dp7vn0b", "Errors.Org.DomainPolicy.NotExisting")
	}
	return &userRemovedFromOrganizationEvent{
		user.NewUserRemovedEvent(ctx, aggregate, human.UserName, human.IDPLinks, domainPolicy.UserLoginMustBeDomain),
	}, nil
}

type userRemovedFromOrganizationEvent struct {
	*user.UserRemovedEvent
}

func (*userRemovedFromOrganizationEvent) EnforceResourceOwner() {}

// moveUserAddEvents add the user to the target organization and replay their
// state. Constraints the removal releases are deleted before these add them
// again, since the eventstore deletes unique constraints before adding them.
func (c *Commands) moveUserAddEvents(ctx context.Context, human *UserV2WriteModel, authenticators *movedAuthenticators, organizationID string) ([]eventstore.Command, error) {
	domainPolicy, err := c.domainPolicyWriteModel(ctx, organizationID)
	if err != nil {
		return nil, zerrors.ThrowPreconditionFailed(err, "COMMAND-mv8dp2xc4h", "Errors.Org.DomainPolicy.NotExisting")
	}
	if err := c.userValidateDomain(ctx, organizationID, human.UserName, domainPolicy.UserLoginMustBeDomain); err != nil {
		return nil, err
	}
	aggregate := &user.NewAggregate(human.AggregateID, organizationID).Aggregate
	added := user.NewHumanAddedEvent(
		ctx,
		aggregate,
		human.UserName,
		human.FirstName,
		human.LastName,
		human.NickName,
		human.DisplayName,
		human.PreferredLanguage,
		human.Gender,
		human.Email,
		domainPolicy.UserLoginMustBeDomain,
	)
	if human.Phone != "" {
		added.AddPhoneData(human.Phone)
	}
	if human.PasswordEncodedHash != "" {
		added.AddPasswordData(human.PasswordEncodedHash, human.PasswordChangeRequired)
	}
	events := []eventstore.Command{added}

	if human.IsEmailVerified {
		events = append(events, user.NewHumanEmailVerifiedEvent(ctx, aggregate))
	}
	if human.Phone != "" && human.IsPhoneVerified {
		events = append(events, user.NewHumanPhoneVerifiedEvent(ctx, aggregate))
	}
	if authenticators.totp != nil {
		events = append(events,
			user.NewHumanOTPAddedEvent(ctx, aggregate, authenticators.totp.Secret),
			user.NewHumanOTPVerifiedEvent(ctx, aggregate, ""),
		)
	}
	if authenticators.otpSMS {
		events = append(events, user.NewHumanOTPSMSAddedEvent(ctx, aggregate))
	}
	if authenticators.otpEmail {
		events = append(events, user.NewHumanOTPEmailAddedEvent(ctx, aggregate))
	}
	for _, token := range authenticators.u2f {
		events = append(events,
			user.NewHumanU2FAddedEvent(ctx, aggregate, token.WebAuthNTokenID, token.Challenge, token.RPID),
			user.NewHumanU2FVerifiedEvent(ctx, aggregate, token.WebAuthNTokenID, token.WebAuthNTokenName, token.AttestationType, token.KeyID, token.PublicKey, token.AAGUID, token.SignCount, ""),
		)
	}
	for _, token := range authenticators.passwordless {
		events = append(events,
			user.NewHumanPasswordlessAddedEvent(ctx, aggregate, token.WebAuthNTokenID, token.Challenge, token.RPID),
			user.NewHumanPasswordlessVerifiedEvent(ctx, aggregate, token.WebAuthNTokenID, token.WebAuthNTokenName, token.AttestationType, token.KeyID, token.PublicKey, token.AAGUID, token.SignCount, ""),
		)
	}
	if len(authenticators.recoveryCodes) > 0 {
		events = append(events, user.NewHumanRecoveryCodesAddedEvent(ctx, aggregate, authenticators.recoveryCodes, nil))
	}
	for _, link := range human.IDPLinks {
		events = append(events, user.NewUserIDPLinkAddedEvent(ctx, aggregate, link.IDPConfigID, link.DisplayName, link.ExternalUserID))
	}
	for key, value := range human.Metadata {
		events = append(events, user.NewMetadataSetEvent(ctx, aggregate, key, value))
	}
	switch human.UserState {
	case domain.UserStateLocked:
		events = append(events, user.NewUserLockedEvent(ctx, aggregate))
	case domain.UserStateInactive:
		events = append(events, user.NewUserDeactivatedEvent(ctx, aggregate))
	}
	return events, nil
}
