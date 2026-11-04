package resources

// Spalk: SCIM creates a user with the command, not through the v2 CreateUser call, so the Actions v2
// executions every other way of creating a user runs (CreateUser's request and response targets) did
// not run for it. Create now runs them on the CreateUserRequest the SCIM user is equivalent to, and
// creates the user that the request targets return.

import (
	"context"
	"net/http"

	"golang.org/x/text/language"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zitadel/zitadel/internal/api/grpc/server/connect_middleware"
	user_grpc "github.com/zitadel/zitadel/internal/api/grpc/user/v2"
	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/crypto"
	"github.com/zitadel/zitadel/internal/execution"
	target_domain "github.com/zitadel/zitadel/internal/execution/target"
	"github.com/zitadel/zitadel/internal/zerrors"
	"github.com/zitadel/zitadel/pkg/grpc/user/v2"
	"github.com/zitadel/zitadel/pkg/grpc/user/v2/userconnect"
)

// Executions is what calling Actions v2 targets needs, as the API's execution interceptor gets it.
type Executions struct {
	TargetEncryption crypto.EncryptionAlgorithm
	ActiveSigningKey execution.GetActiveSigningWebKey
	HTTPClient       *http.Client
}

// createUserMethod is the call whose executions a SCIM user creation runs.
const createUserMethod = userconnect.UserServiceCreateUserProcedure

// createUserExecution is a SCIM user creation's run of createUserMethod's executions.
type createUserExecution struct {
	// request is the CreateUserRequest after the request targets.
	request         *user.CreateUserRequest
	responseTargets []target_domain.Target
}

// executeCreateUserRequest runs createUserMethod's request targets on the CreateUserRequest equivalent
// to human, and changes human and scimUser to the request they return. It returns nil, changing nothing,
// when createUserMethod has no executions. A target's refusal is its error.
func (h *UsersHandler) executeCreateUserRequest(ctx context.Context, orgID string, scimUser *ScimUser, human *command.AddHuman) (*createUserExecution, error) {
	requestTargets := execution.QueryExecutionTargetsForRequest(ctx, createUserMethod)
	responseTargets := execution.QueryExecutionTargetsForResponse(ctx, createUserMethod)
	if len(requestTargets) == 0 && len(responseTargets) == 0 {
		return nil, nil
	}
	run := &createUserExecution{
		request:         addHumanToCreateUserRequest(orgID, human),
		responseTargets: responseTargets,
	}
	if len(requestTargets) == 0 {
		return run, nil
	}
	if err := connect_middleware.ExecuteRequestTargets(ctx, requestTargets, createUserMethod, run.request, nil, h.executions.TargetEncryption, h.executions.ActiveSigningKey, h.executions.HTTPClient); err != nil {
		return nil, err
	}

	req := run.request
	// the organization is SCIM's, from the path the caller is authorized for
	if req.GetOrganizationId() != orgID {
		return nil, zerrors.ThrowInvalidArgument(nil, "SCIM-EXo1", "Errors.Execution.Failed")
	}
	if req.GetHuman() == nil {
		return nil, zerrors.ThrowInvalidArgument(nil, "SCIM-EXh1", "Errors.Execution.Failed")
	}
	changed, err := user_grpc.CreateHumanRequestToAddHuman(req.GetHuman(), orgID, req.Username, req.UserId, req.GetMetadata())
	if err != nil {
		return nil, err
	}
	// a CreateUserRequest has no state
	changed.SetInactive = human.SetInactive
	applyAddHumanToScimUser(scimUser, human, changed)
	*human = *changed
	return run, nil
}

// executeCreateUserResponse runs createUserMethod's response targets for the created human.
// SCIM answers with its own resource, so a target's replacement of the response is not used.
func (h *UsersHandler) executeCreateUserResponse(ctx context.Context, run *createUserExecution, human *command.AddHuman) error {
	if run == nil || len(run.responseTargets) == 0 {
		return nil
	}
	resp := &user.CreateUserResponse{
		Id:           human.ID,
		CreationDate: timestamppb.New(human.Details.EventDate),
		EmailCode:    human.EmailCode,
		PhoneCode:    human.PhoneCode,
	}
	return connect_middleware.ExecuteResponseTargets(ctx, run.responseTargets, createUserMethod, run.request, resp, nil, h.executions.TargetEncryption, h.executions.ActiveSigningKey, h.executions.HTTPClient)
}

// addHumanToCreateUserRequest is the v2 CreateUserRequest that creates human in the organization orgID,
// as CreateHumanRequestToAddHuman converts it back.
func addHumanToCreateUserRequest(orgID string, human *command.AddHuman) *user.CreateUserRequest {
	profile := &user.SetHumanProfile{
		GivenName:  human.FirstName,
		FamilyName: human.LastName,
	}
	if human.NickName != "" {
		profile.NickName = &human.NickName
	}
	if human.DisplayName != "" {
		profile.DisplayName = &human.DisplayName
	}
	if human.PreferredLanguage != language.Und {
		lang := human.PreferredLanguage.String()
		profile.PreferredLanguage = &lang
	}
	email := &user.SetHumanEmail{Email: string(human.Email.Address)}
	if human.Email.Verified {
		email.Verification = &user.SetHumanEmail_IsVerified{IsVerified: true}
	}
	h := &user.CreateUserRequest_Human{
		Profile: profile,
		Email:   email,
	}
	if human.Phone.Number != "" {
		h.Phone = &user.SetHumanPhone{Phone: string(human.Phone.Number)}
		if human.Phone.Verified {
			h.Phone.Verification = &user.SetHumanPhone_IsVerified{IsVerified: true}
		}
	}
	if human.Password != "" {
		h.PasswordType = &user.CreateUserRequest_Human_Password{Password: &user.Password{Password: human.Password}}
	}
	req := &user.CreateUserRequest{
		OrganizationId: orgID,
		Username:       &human.Username,
		UserType:       &user.CreateUserRequest_Human_{Human: h},
	}
	for _, md := range human.Metadata {
		req.Metadata = append(req.Metadata, &user.Metadata{Key: md.Key, Value: md.Value})
	}
	return req
}

// applyAddHumanToScimUser changes the SCIM user's fields that a target changed from before to after.
// Email and phone are taken from the created user (mapAddCommandToScimUser), and metadata on the next read.
func applyAddHumanToScimUser(scimUser *ScimUser, before, after *command.AddHuman) {
	if after.Username != before.Username {
		scimUser.UserName = after.Username
	}
	if after.NickName != before.NickName {
		scimUser.NickName = after.NickName
	}
	if after.DisplayName != before.DisplayName {
		scimUser.DisplayName = after.DisplayName
	}
	if after.PreferredLanguage != before.PreferredLanguage {
		scimUser.PreferredLanguage = after.PreferredLanguage
	}
	if after.FirstName == before.FirstName && after.LastName == before.LastName {
		return
	}
	if scimUser.Name == nil {
		scimUser.Name = new(ScimUserName)
	}
	scimUser.Name.GivenName = after.FirstName
	scimUser.Name.FamilyName = after.LastName
}
