package resources

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/command"
	"github.com/zitadel/zitadel/internal/domain"
	target_domain "github.com/zitadel/zitadel/internal/execution/target"
	"github.com/zitadel/zitadel/internal/zerrors"
)

// targetServer is a Call target that records the bodies it is posted and answers with reply.
type targetServer struct {
	bodies [][]byte
	reply  string
	server *httptest.Server
}

func newTargetServer(t *testing.T, reply string) *targetServer {
	s := &targetServer{reply: reply}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		s.bodies = append(s.bodies, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, s.reply)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *targetServer) target(executionID string) target_domain.Target {
	return target_domain.Target{
		ExecutionID:      executionID,
		TargetID:         executionID,
		TargetType:       target_domain.TargetTypeCall,
		Endpoint:         s.server.URL,
		Timeout:          10 * time.Second,
		InterruptOnError: true,
		PayloadType:      target_domain.PayloadTypeJSON,
	}
}

const (
	testCallerID = "scim-machine-user"
	testOrgID    = "org1"
)

// executionContext is a SCIM call by testCallerID into testOrgID, with the targets as executions.
func executionContext(targets ...target_domain.Target) context.Context {
	ctx := authz.SetCtxData(context.Background(), authz.CtxData{UserID: testCallerID, OrgID: testOrgID})
	return authz.WithExecutionRouter(ctx, target_domain.NewRouter(targets))
}

func testExecutionsHandler() *UsersHandler {
	return &UsersHandler{executions: Executions{HTTPClient: http.DefaultClient}}
}

func testAddHuman() *command.AddHuman {
	return &command.AddHuman{
		Username:          "bjensen",
		FirstName:         "Barbara",
		LastName:          "Jensen",
		NickName:          "Babs",
		DisplayName:       "Babs Jensen",
		PreferredLanguage: language.English,
		Email:             command.Email{Address: "bjensen@example.com", Verified: true},
		Phone:             command.Phone{Number: "+41791234567", Verified: true},
		Password:          "Password1!",
		SetInactive:       true,
		Metadata: []*command.AddMetadataEntry{
			{Key: "urn:zitadel:scim:externalId", Value: []byte("701984")},
		},
	}
}

func testScimUser() *ScimUser {
	return &ScimUser{
		UserName:    "bjensen",
		NickName:    "Babs",
		DisplayName: "Babs Jensen",
		Name:        &ScimUserName{GivenName: "Barbara", FamilyName: "Jensen"},
	}
}

// wantCreateUserRequestPayload is what a request target is posted for testAddHuman.
const wantCreateUserRequestPayload = `{
	"fullMethod": "/zitadel.user.v2.UserService/CreateUser",
	"orgID": "org1",
	"userID": "scim-machine-user",
	"request": {
		"organizationId": "org1",
		"username": "bjensen",
		"human": {
			"profile": {
				"givenName": "Barbara",
				"familyName": "Jensen",
				"nickName": "Babs",
				"displayName": "Babs Jensen",
				"preferredLanguage": "en"
			},
			"email": {"email": "bjensen@example.com", "isVerified": true},
			"phone": {"phone": "+41791234567", "isVerified": true},
			"password": {"password": "Password1!"}
		},
		"metadata": [{"key": "urn:zitadel:scim:externalId", "value": "NzAxOTg0"}]
	}
}`

func TestUsersHandler_executeCreateUserRequest(t *testing.T) {
	const requestID = "request/zitadel.user.v2.UserService/CreateUser"

	t.Run("no executions changes nothing", func(t *testing.T) {
		human, scimUser := testAddHuman(), testScimUser()
		run, err := testExecutionsHandler().executeCreateUserRequest(executionContext(), testOrgID, scimUser, human)
		require.NoError(t, err)
		assert.Nil(t, run)
		assert.Equal(t, testAddHuman(), human)
		assert.Equal(t, testScimUser(), scimUser)
		assert.NoError(t, testExecutionsHandler().executeCreateUserResponse(executionContext(), run, human))
	})

	t.Run("posts the CreateUserRequest with the SCIM caller and creates what the target returns", func(t *testing.T) {
		reply := `{
			"organizationId": "org1",
			"userId": "6f1b3c2a-1d4e-4f5a-9b8c-7d6e5f4a3b2c",
			"username": "bjensen7",
			"human": {
				"profile": {"givenName": "Barbara", "familyName": "Jensen", "nickName": "Babs", "displayName": "Babs Jensen", "preferredLanguage": "en"},
				"email": {"email": "bjensen@example.com", "isVerified": true},
				"phone": {"phone": "+41791234567", "isVerified": true},
				"password": {"password": "Password1!"}
			},
			"metadata": [
				{"key": "urn:zitadel:scim:externalId", "value": "NzAxOTg0"},
				{"key": "spalk:scim-provisioned", "value": "dHJ1ZQ=="},
				{"key": "spalk:managed-by", "value": "b3JnMQ=="}
			]
		}`
		srv := newTargetServer(t, reply)
		human, scimUser := testAddHuman(), testScimUser()

		run, err := testExecutionsHandler().executeCreateUserRequest(executionContext(srv.target(requestID)), testOrgID, scimUser, human)
		require.NoError(t, err)
		require.Len(t, srv.bodies, 1)
		assert.JSONEq(t, wantCreateUserRequestPayload, string(srv.bodies[0]))

		want := testAddHuman()
		want.ID = "6f1b3c2a-1d4e-4f5a-9b8c-7d6e5f4a3b2c"
		want.Username = "bjensen7"
		want.Email.NoEmailVerification = true
		want.Metadata = append(want.Metadata,
			&command.AddMetadataEntry{Key: "spalk:scim-provisioned", Value: []byte("true")},
			&command.AddMetadataEntry{Key: "spalk:managed-by", Value: []byte("org1")},
		)
		want.Links = []*command.AddLink{}
		assert.Equal(t, want, human)
		wantScimUser := testScimUser()
		wantScimUser.UserName = "bjensen7"
		assert.Equal(t, wantScimUser, scimUser)
		assert.Equal(t, "bjensen7", run.request.GetUsername())
	})

	t.Run("an empty reply keeps the user", func(t *testing.T) {
		srv := newTargetServer(t, "")
		human, scimUser := testAddHuman(), testScimUser()
		_, err := testExecutionsHandler().executeCreateUserRequest(executionContext(srv.target(requestID)), testOrgID, scimUser, human)
		require.NoError(t, err)
		want := testAddHuman()
		want.Email.NoEmailVerification = true // only has a meaning for an unverified email
		want.Links = []*command.AddLink{}
		assert.Equal(t, want, human)
		assert.Equal(t, testScimUser(), scimUser)
	})

	refusals := []struct {
		name    string
		status  int
		isError func(error) bool
	}{
		{"conflict", http.StatusConflict, zerrors.IsErrorAlreadyExists},
		{"forbidden", http.StatusForbidden, zerrors.IsPermissionDenied},
		{"bad request", http.StatusBadRequest, zerrors.IsErrorInvalidArgument},
		{"unavailable", http.StatusServiceUnavailable, zerrors.IsPreconditionFailed},
	}
	for _, r := range refusals {
		t.Run("a refusal is its error: "+r.name, func(t *testing.T) {
			b, _ := json.Marshal(map[string]any{"forwardedStatusCode": r.status, "forwardedErrorMessage": "That username is taken."})
			srv := newTargetServer(t, string(b))
			human := testAddHuman()
			_, err := testExecutionsHandler().executeCreateUserRequest(executionContext(srv.target(requestID)), testOrgID, testScimUser(), human)
			require.Error(t, err)
			assert.True(t, r.isError(err), err)
			zErr, ok := zerrors.AsZitadelError(err)
			require.True(t, ok)
			assert.Equal(t, "That username is taken.", zErr.GetMessage())
			assert.Equal(t, testAddHuman(), human)
		})
	}

	invalid := []struct {
		name  string
		reply string
	}{
		{"another organization", `{"organizationId": "org2", "human": {"profile": {}, "email": {"email": "a@b.c"}}}`},
		{"a machine", `{"organizationId": "org1", "machine": {"name": "m"}}`},
		{"conflicting metadata", `{"organizationId": "org1", "human": {"profile": {}, "email": {"email": "a@b.c"}, "metadata": [{"key": "a", "value": "Yg=="}]}, "metadata": [{"key": "a", "value": "Yg=="}]}`},
	}
	for _, i := range invalid {
		t.Run("a reply with "+i.name+" is refused", func(t *testing.T) {
			srv := newTargetServer(t, i.reply)
			human := testAddHuman()
			_, err := testExecutionsHandler().executeCreateUserRequest(executionContext(srv.target(requestID)), testOrgID, testScimUser(), human)
			assert.True(t, zerrors.IsErrorInvalidArgument(err), err)
			assert.Equal(t, testAddHuman(), human)
		})
	}
}

func TestUsersHandler_executeCreateUserResponse(t *testing.T) {
	srv := newTargetServer(t, "")
	ctx := executionContext(srv.target("response/zitadel.user.v2.UserService/CreateUser"))
	human, scimUser := testAddHuman(), testScimUser()
	h := testExecutionsHandler()

	run, err := h.executeCreateUserRequest(ctx, testOrgID, scimUser, human)
	require.NoError(t, err)
	assert.Empty(t, srv.bodies, "no request target")
	assert.Equal(t, testAddHuman(), human)

	human.ID = "user1"
	human.Details = &domain.ObjectDetails{EventDate: time.Date(2026, 11, 5, 1, 2, 3, 0, time.UTC)}
	require.NoError(t, h.executeCreateUserResponse(ctx, run, human))
	require.Len(t, srv.bodies, 1)
	var payload map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(srv.bodies[0], &payload))
	var want map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(wantCreateUserRequestPayload), &want))
	assert.JSONEq(t, string(want["request"]), string(payload["request"]))
	assert.JSONEq(t, `{"id": "user1", "creationDate": "2026-11-05T01:02:03Z"}`, string(payload["response"]))
	assert.JSONEq(t, `"scim-machine-user"`, string(payload["userID"]))

	t.Run("a refusal is its error", func(t *testing.T) {
		srv.reply = `{"forwardedStatusCode": 403, "forwardedErrorMessage": "no"}`
		assert.True(t, zerrors.IsPermissionDenied(h.executeCreateUserResponse(ctx, run, human)))
	})
}

func Test_addHumanToCreateUserRequest_unset(t *testing.T) {
	req := addHumanToCreateUserRequest(testOrgID, &command.AddHuman{
		Username: "u",
		Email:    command.Email{Address: "u@example.com"},
	})
	b, err := protojson.Marshal(req)
	require.NoError(t, err)
	assert.JSONEq(t, `{"organizationId": "org1", "username": "u", "human": {"profile": {}, "email": {"email": "u@example.com"}}}`, string(b))
}

func Test_applyAddHumanToScimUser(t *testing.T) {
	before := testAddHuman()
	after := *before
	after.NickName = "B"
	after.DisplayName = "B J"
	after.PreferredLanguage = language.German
	after.LastName = "Jensen-Smith"
	scimUser := &ScimUser{UserName: "bjensen"}

	applyAddHumanToScimUser(scimUser, before, &after)
	assert.Equal(t, &ScimUser{
		UserName:          "bjensen",
		NickName:          "B",
		DisplayName:       "B J",
		PreferredLanguage: language.German,
		Name:              &ScimUserName{GivenName: "Barbara", FamilyName: "Jensen-Smith"},
	}, scimUser)
}
