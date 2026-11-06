package command

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"

	"github.com/zitadel/zitadel/internal/api/authz"
	"github.com/zitadel/zitadel/internal/crypto"
	"github.com/zitadel/zitadel/internal/domain"
	"github.com/zitadel/zitadel/internal/eventstore"
	"github.com/zitadel/zitadel/internal/repository/org"
	"github.com/zitadel/zitadel/internal/repository/user"
	"github.com/zitadel/zitadel/internal/zerrors"
)

func TestCommandSide_LockUserV2(t *testing.T) {
	userAgg := &user.NewAggregate("user1", "org1").Aggregate
	type fields struct {
		eventstore      func(*testing.T) *eventstore.Eventstore
		checkPermission domain.PermissionCheck
	}
	type (
		args struct {
			ctx    context.Context
			userID string
		}
	)
	type res struct {
		want *domain.ObjectDetails
		err  func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "userid missing, invalid argument error",
			fields: fields{
				eventstore:      expectEventstore(),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowInvalidArgument(nil, "COMMAND-agz3eczifm", "Errors.User.UserIDMissing"))
				},
			},
		},
		{
			name: "user not existing, not found error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowNotFound(nil, "COMMAND-450yxuqrh1", "Errors.User.NotFound"))
				},
			},
		},
		{
			name: "user already locked, precondition error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewUserLockedEvent(context.Background(),
								userAgg,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPreconditionFailed(nil, "COMMAND-lgws8wtsqf", "Errors.User.ShouldBeActiveOrInitial"))
				},
			},
		},
		{
			name: "user already locked, precondition error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewMachineAddedEvent(context.Background(),
								userAgg,
								"username",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
						eventFromEventPusher(
							user.NewUserLockedEvent(context.Background(),
								userAgg,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPreconditionFailed(nil, "COMMAND-lgws8wtsqf", "Errors.User.ShouldBeActiveOrInitial"))
				},
			},
		},
		{
			name: "lock user, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
					),
					expectPush(
						user.NewUserLockedEvent(context.Background(),
							userAgg,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
		{
			name: "lock user, no permission",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckNotAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPermissionDenied(nil, "AUTHZ-HKJD33", "Errors.PermissionDenied"))
				},
			},
		},
		{
			name: "lock user machine, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewMachineAddedEvent(context.Background(),
								userAgg,
								"username",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
					),
					expectPush(
						user.NewUserLockedEvent(context.Background(),
							userAgg,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:      tt.fields.eventstore(t),
				checkPermission: tt.fields.checkPermission,
			}
			got, err := r.LockUserV2(tt.args.ctx, tt.args.userID)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
			if tt.res.err == nil {
				assertObjectDetails(t, tt.res.want, got)
			}
		})
	}
}

func TestCommandSide_UnlockUserV2(t *testing.T) {
	userAgg := &user.NewAggregate("user1", "org1").Aggregate
	type fields struct {
		eventstore      func(*testing.T) *eventstore.Eventstore
		checkPermission domain.PermissionCheck
	}
	type (
		args struct {
			ctx    context.Context
			userID string
		}
	)
	type res struct {
		want *domain.ObjectDetails
		err  func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "userid missing, invalid argument error",
			fields: fields{
				eventstore:      expectEventstore(),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowInvalidArgument(nil, "COMMAND-a9ld4xckax", "Errors.User.UserIDMissing"))
				},
			},
		},
		{
			name: "user not existing, not found error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowNotFound(nil, "COMMAND-x377t913pw", "Errors.User.NotFound"))
				},
			},
		},
		{
			name: "user already active, precondition error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPreconditionFailed(nil, "COMMAND-olb9vb0oca", "Errors.User.NotLocked"))
				},
			},
		},
		{
			name: "user already active, precondition error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						user.NewMachineAddedEvent(context.Background(),
							userAgg,
							"username",
							"name",
							"description",
							true,
							domain.OIDCTokenTypeBearer,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPreconditionFailed(nil, "COMMAND-olb9vb0oca", "Errors.User.NotLocked"))
				},
			},
		},
		{
			name: "unlock user, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewUserLockedEvent(context.Background(),
								userAgg),
						),
					),
					expectPush(
						user.NewUserUnlockedEvent(context.Background(),
							userAgg,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
		{
			name: "unlock user, no permission",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewUserLockedEvent(context.Background(),
								userAgg),
						),
					),
				),
				checkPermission: newMockPermissionCheckNotAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPermissionDenied(nil, "AUTHZ-HKJD33", "Errors.PermissionDenied"))
				},
			},
		},
		{
			name: "unlock user machine, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewMachineAddedEvent(context.Background(),
								userAgg,
								"username",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
						eventFromEventPusher(
							user.NewUserLockedEvent(context.Background(),
								userAgg),
						),
					),
					expectPush(
						user.NewUserUnlockedEvent(context.Background(),
							userAgg,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:      tt.fields.eventstore(t),
				checkPermission: tt.fields.checkPermission,
			}
			got, err := r.UnlockUserV2(tt.args.ctx, tt.args.userID)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
			if tt.res.err == nil {
				assertObjectDetails(t, tt.res.want, got)
			}
		})
	}
}

func TestCommandSide_DeactivateUserV2(t *testing.T) {
	userAgg := &user.NewAggregate("user1", "org1").Aggregate
	type fields struct {
		eventstore      func(*testing.T) *eventstore.Eventstore
		checkPermission domain.PermissionCheck
	}
	type (
		args struct {
			ctx    context.Context
			userID string
		}
	)
	type res struct {
		want *domain.ObjectDetails
		err  func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "userid missing, invalid argument error",
			fields: fields{
				eventstore:      expectEventstore(),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowInvalidArgument(nil, "COMMAND-78iiirat8y", "Errors.User.UserIDMissing"))
				},
			},
		},
		{
			name: "user not existing, not found error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowNotFound(nil, "COMMAND-5gp2p62iin", "Errors.User.NotFound"))
				},
			},
		},
		{
			name: "user initial, precondition error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewHumanInitialCodeAddedEvent(context.Background(),
								userAgg,
								nil, time.Hour*1,
								"",
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPreconditionFailed(nil, "COMMAND-gvx4kct9r2", "Errors.User.CantDeactivateInitial"))
				},
			},
		},
		{
			name: "user already inactive, precondition error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewUserDeactivatedEvent(context.Background(),
								userAgg,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPreconditionFailed(nil, "COMMAND-5gunjw0cd7", "Errors.User.AlreadyInactive"))
				},
			},
		},
		{
			name: "deactivate user, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewHumanInitializedCheckSucceededEvent(context.Background(),
								userAgg,
							),
						),
					),
					expectPush(
						user.NewUserDeactivatedEvent(context.Background(),
							userAgg,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
		{
			name: "deactivate user, no permission",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewHumanInitializedCheckSucceededEvent(context.Background(),
								userAgg,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckNotAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPermissionDenied(nil, "AUTHZ-HKJD33", "Errors.PermissionDenied"))
				},
			},
		},
		{
			name: "user machine already inactive, precondition error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewMachineAddedEvent(context.Background(),
								userAgg,
								"username",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
						eventFromEventPusher(
							user.NewUserDeactivatedEvent(context.Background(),
								userAgg,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPreconditionFailed(nil, "COMMAND-5gunjw0cd7", "Errors.User.AlreadyInactive"))
				},
			},
		},
		{
			name: "deactivate user machine, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewMachineAddedEvent(context.Background(),
								userAgg,
								"username",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
					),
					expectPush(
						user.NewUserDeactivatedEvent(context.Background(),
							userAgg,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:      tt.fields.eventstore(t),
				checkPermission: tt.fields.checkPermission,
			}
			got, err := r.DeactivateUserV2(tt.args.ctx, tt.args.userID)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
			if tt.res.err == nil {
				assertObjectDetails(t, tt.res.want, got)
			}
		})
	}
}

func TestCommandSide_ReactivateUserV2(t *testing.T) {
	userAgg := &user.NewAggregate("user1", "org1").Aggregate
	type fields struct {
		eventstore      func(*testing.T) *eventstore.Eventstore
		checkPermission domain.PermissionCheck
	}
	type (
		args struct {
			ctx    context.Context
			userID string
		}
	)
	type res struct {
		want *domain.ObjectDetails
		err  func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "userid missing, invalid argument error",
			fields: fields{
				eventstore:      expectEventstore(),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowInvalidArgument(nil, "COMMAND-0nx1ie38fw", "Errors.User.UserIDMissing"))
				},
			},
		},
		{
			name: "user not existing, not found error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowNotFound(nil, "COMMAND-9hy5kzbuk6", "Errors.User.NotFound"))
				},
			},
		},
		{
			name: "user already active, precondition error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPreconditionFailed(nil, "COMMAND-s5qqcz97hf", "Errors.User.NotInactive"))
				},
			},
		},
		{
			name: "user machine already active, precondition error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewMachineAddedEvent(context.Background(),
								userAgg,
								"username",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPreconditionFailed(nil, "COMMAND-s5qqcz97hf", "Errors.User.NotInactive"))
				},
			},
		},
		{
			name: "reactivate user, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewUserDeactivatedEvent(context.Background(),
								userAgg),
						),
					),
					expectPush(
						user.NewUserReactivatedEvent(context.Background(),
							userAgg,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
		{
			name: "reactivate user, no permission",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(context.Background(),
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewUserDeactivatedEvent(context.Background(),
								userAgg),
						),
					),
				),
				checkPermission: newMockPermissionCheckNotAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowPermissionDenied(nil, "AUTHZ-HKJD33", "Errors.PermissionDenied"))
				},
			},
		},
		{
			name: "reactivate user machine, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewMachineAddedEvent(context.Background(),
								userAgg,
								"username",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
						eventFromEventPusher(
							user.NewUserDeactivatedEvent(context.Background(),
								userAgg),
						),
					),
					expectPush(
						user.NewUserReactivatedEvent(context.Background(),
							userAgg,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				ctx:    context.Background(),
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:      tt.fields.eventstore(t),
				checkPermission: tt.fields.checkPermission,
			}
			got, err := r.ReactivateUserV2(tt.args.ctx, tt.args.userID)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
			if tt.res.err == nil {
				assertObjectDetails(t, tt.res.want, got)
			}
		})
	}
}

func TestCommandSide_RemoveUserV2(t *testing.T) {
	ctxUserID := "ctxUserID"
	ctx := authz.SetCtxData(context.Background(), authz.CtxData{UserID: ctxUserID})
	userAgg := &user.NewAggregate("user1", "org1").Aggregate
	orgAgg := &org.NewAggregate("org1").Aggregate
	type fields struct {
		eventstore      func(*testing.T) *eventstore.Eventstore
		checkPermission domain.PermissionCheck
	}
	type (
		args struct {
			userID               string
			cascadingMemberships []*CascadingMembership
			grantIDs             []string
		}
	)
	type res struct {
		want *domain.ObjectDetails
		err  func(error) bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		res    res
	}{
		{
			name: "userid missing, invalid argument error",
			fields: fields{
				eventstore:      expectEventstore(),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				userID: "",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowInvalidArgument(nil, "COMMAND-vaipl7s13l", "Errors.User.UserIDMissing"))
				},
			},
		},
		{
			name: "user not existing, not found error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowNotFound(nil, "COMMAND-bd4ir1mblj", "Errors.User.NotFound"))
				},
			},
		},
		{
			name: "user removed, notfound error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(ctx,
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewUserRemovedEvent(ctx,
								userAgg,
								"username",
								nil,
								true,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowNotFound(nil, "COMMAND-bd4ir1mblj", "Errors.User.NotFound"))
				},
			},
		},
		{
			name: "remove user, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(ctx,
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
					),
					expectFilter(
						eventFromEventPusher(
							org.NewDomainPolicyAddedEvent(context.Background(),
								orgAgg,
								true,
								true,
								true,
							),
						),
					),
					expectPush(
						user.NewUserRemovedEvent(ctx,
							userAgg,
							"username",
							nil,
							true,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
		{
			name: "remove user, no permission",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(ctx,
								userAgg,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
						eventFromEventPusher(
							user.NewHumanInitializedCheckSucceededEvent(ctx,
								userAgg,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckNotAllowed(),
			},
			args: args{
				userID: "user1",
			},
			res: res{
				err: zerrors.IsPermissionDenied,
			},
		},
		{
			name: "user machine already removed, notfound error",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewMachineAddedEvent(ctx,
								userAgg,
								"username",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
						eventFromEventPusher(
							user.NewUserRemovedEvent(ctx,
								userAgg,
								"username",
								nil,
								true,
							),
						),
					),
				),
			},
			args: args{
				userID: "user1",
			},
			res: res{
				err: func(err error) bool {
					return errors.Is(err, zerrors.ThrowNotFound(nil, "COMMAND-bd4ir1mblj", "Errors.User.NotFound"))
				},
			},
		},
		{
			name: "remove user machine, ok",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewMachineAddedEvent(ctx,
								userAgg,
								"username",
								"name",
								"description",
								true,
								domain.OIDCTokenTypeBearer,
							),
						),
					),
					expectFilter(
						eventFromEventPusher(
							org.NewDomainPolicyAddedEvent(context.Background(),
								orgAgg,
								true,
								true,
								true,
							),
						),
					),
					expectPush(
						user.NewUserRemovedEvent(ctx,
							userAgg,
							"username",
							nil,
							true,
						),
					),
				),
				checkPermission: newMockPermissionCheckAllowed(),
			},
			args: args{
				userID: "user1",
			},
			res: res{
				want: &domain.ObjectDetails{
					ResourceOwner: "org1",
				},
			},
		},
		{
			name: "remove self, permission denied",
			fields: fields{
				eventstore: expectEventstore(
					expectFilter(
						eventFromEventPusher(
							user.NewHumanAddedEvent(ctx,
								&user.NewAggregate(ctxUserID, "org1").Aggregate,
								"username",
								"firstname",
								"lastname",
								"nickname",
								"displayname",
								language.German,
								domain.GenderUnspecified,
								"email@test.ch",
								true,
							),
						),
					),
				),
				checkPermission: newMockPermissionCheckNotAllowed(),
			},
			args: args{
				userID: ctxUserID,
			},
			res: res{
				err: zerrors.IsPermissionDenied,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Commands{
				eventstore:      tt.fields.eventstore(t),
				checkPermission: tt.fields.checkPermission,
			}

			got, err := r.RemoveUserV2(ctx, tt.args.userID, "", tt.args.cascadingMemberships, tt.args.grantIDs...)
			if tt.res.err == nil {
				assert.NoError(t, err)
			}
			if tt.res.err != nil && !tt.res.err(err) {
				t.Errorf("got wrong err: %v ", err)
			}
			if tt.res.err == nil {
				assertObjectDetails(t, tt.res.want, got)
			}
		})
	}
}

func TestCommandSide_RemoveUserV2OwnerDeleteReady(t *testing.T) {
	ctxUserID := "ctxUserID"
	ctx := authz.SetCtxData(context.Background(), authz.CtxData{UserID: ctxUserID})
	userAgg := &user.NewAggregate("user1", "org1").Aggregate
	orgAgg := &org.NewAggregate("org1").Aggregate
	r := &Commands{
		eventstore: expectEventstore(
			expectFilter(
				eventFromEventPusher(
					user.NewHumanAddedEvent(ctx,
						userAgg,
						"username",
						"firstname",
						"lastname",
						"nickname",
						"displayname",
						language.German,
						domain.GenderUnspecified,
						"email@test.ch",
						true,
					),
				),
			),
			expectFilter(
				eventFromEventPusher(
					org.NewDomainPolicyAddedEvent(context.Background(),
						orgAgg,
						true,
						true,
						true,
					),
				),
			),
			expectPush(
				user.NewUserRemovedByOwnerEvent(ctx, userAgg),
			),
		)(t),
		checkPermission:  newMockPermissionCheckAllowed(),
		ownerDeleteReady: func(context.Context) (bool, error) { return true, nil },
	}
	assertOwnerOnlyUniqueConstraints(t, user.NewUserRemovedByOwnerEvent(ctx, userAgg), eventstore.UniqueConstraintOwnerUser, "user1")
	got, err := r.RemoveUserV2(ctx, "user1", "", nil)
	assert.NoError(t, err)
	assertObjectDetails(t, &domain.ObjectDetails{ResourceOwner: "org1"}, got)
}

func TestCommandSide_MoveUser(t *testing.T) {
	ctx := authz.SetCtxData(context.Background(), authz.CtxData{UserID: "ctxUserID"})
	fromAgg := &user.NewAggregate("user1", "org1").Aggregate
	toAgg := &user.NewAggregate("user1", "org2").Aggregate
	secret := &crypto.CryptoValue{CryptoType: crypto.TypeEncryption, Algorithm: "enc", KeyID: "id", Crypted: []byte("totp")}

	humanAdded := func(agg *eventstore.Aggregate) *user.HumanAddedEvent {
		e := user.NewHumanAddedEvent(ctx, agg, "username", "firstname", "lastname", "nickname", "displayname",
			language.German, domain.GenderUnspecified, "email@test.ch", true)
		e.AddPhoneData("+41791234567")
		e.AddPasswordData("$2a$10$hash", false)
		return e
	}
	// userEvents is the user's history in org1, with every kind of state that moves.
	userEvents := func() []eventstore.Event {
		return []eventstore.Event{
			eventFromEventPusher(humanAdded(fromAgg)),
			eventFromEventPusher(user.NewHumanEmailVerifiedEvent(ctx, fromAgg)),
			eventFromEventPusher(user.NewHumanPhoneVerifiedEvent(ctx, fromAgg)),
			eventFromEventPusher(user.NewUserIDPLinkAddedEvent(ctx, fromAgg, "idp1", "display", "external1")),
			eventFromEventPusher(user.NewMetadataSetEvent(ctx, fromAgg, "key", []byte("value"))),
			eventFromEventPusher(user.NewUserLockedEvent(ctx, fromAgg)),
		}
	}
	orgExists := expectFilter(eventFromEventPusher(org.NewOrgAddedEvent(context.Background(), &org.NewAggregate("org2").Aggregate, "org2")))
	domainPolicy := func(orgID string) expect {
		return expectFilter(eventFromEventPusher(org.NewDomainPolicyAddedEvent(context.Background(), &org.NewAggregate(orgID).Aggregate, true, true, true)))
	}
	// authenticatorFilters answer the TOTP, OTP SMS, OTP email, recovery code,
	// U2F and passkey reads, with a TOTP and a U2F key set up.
	authenticatorFilters := []expect{
		expectFilter(
			eventFromEventPusher(user.NewHumanOTPAddedEvent(ctx, fromAgg, secret)),
			eventFromEventPusher(user.NewHumanOTPVerifiedEvent(ctx, fromAgg, "agent1")),
		),
		expectFilter(),
		expectFilter(),
		expectFilter(),
		expectFilter(
			eventFromEventPusher(user.NewHumanU2FAddedEvent(ctx, fromAgg, "u2f1", "challenge", "rp")),
			eventFromEventPusher(user.NewHumanU2FVerifiedEvent(ctx, fromAgg, "u2f1", "key", "none", []byte("keyid"), []byte("pub"), []byte("aaguid"), 3, "agent1")),
		),
		expectFilter(),
	}

	tests := []struct {
		name           string
		organizationID string
		expects        []expect
		permission     domain.PermissionCheck
		wantErr        func(error) bool
	}{
		{
			name:           "missing organization",
			organizationID: "",
			wantErr:        zerrors.IsErrorInvalidArgument,
		},
		{
			name:           "user not found",
			organizationID: "org2",
			expects:        []expect{expectFilter()},
			wantErr:        zerrors.IsNotFound,
		},
		{
			name:           "service account",
			organizationID: "org2",
			expects: []expect{expectFilter(eventFromEventPusher(
				user.NewMachineAddedEvent(ctx, fromAgg, "machine", "name", "description", true, domain.OIDCTokenTypeBearer),
			))},
			wantErr: zerrors.IsPreconditionFailed,
		},
		{
			name:           "already in the organization",
			organizationID: "org1",
			expects:        []expect{expectFilter(userEvents()...)},
			wantErr:        zerrors.IsPreconditionFailed,
		},
		{
			name:           "no permission",
			organizationID: "org2",
			expects:        []expect{expectFilter(userEvents()...)},
			permission:     newMockPermissionCheckNotAllowed(),
			wantErr:        zerrors.IsPermissionDenied,
		},
		{
			name:           "target organization not found",
			organizationID: "org2",
			expects:        []expect{expectFilter(userEvents()...), expectFilter()},
			wantErr:        zerrors.IsPreconditionFailed,
		},
		{
			name:           "moves the user with their state",
			organizationID: "org2",
			expects: append(append(
				[]expect{expectFilter(userEvents()...), orgExists, expectFilter(userEvents()...)},
				authenticatorFilters...),
				domainPolicy("org2"),
				expectPush(
					user.NewUserRemovedByOwnerEvent(ctx, fromAgg),
					humanAdded(toAgg),
					user.NewHumanEmailVerifiedEvent(ctx, toAgg),
					user.NewHumanPhoneVerifiedEvent(ctx, toAgg),
					user.NewHumanOTPAddedEvent(ctx, toAgg, secret),
					user.NewHumanOTPVerifiedEvent(ctx, toAgg, ""),
					user.NewHumanU2FAddedEvent(ctx, toAgg, "u2f1", "challenge", "rp"),
					user.NewHumanU2FVerifiedEvent(ctx, toAgg, "u2f1", "key", "none", []byte("keyid"), []byte("pub"), []byte("aaguid"), 3, ""),
					user.NewUserIDPLinkAddedEvent(ctx, toAgg, "idp1", "display", "external1"),
					user.NewMetadataSetEvent(ctx, toAgg, "key", []byte("value")),
					user.NewUserLockedEvent(ctx, toAgg),
				),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permission := tt.permission
			if permission == nil {
				permission = newMockPermissionCheckAllowed()
			}
			r := &Commands{
				eventstore:       expectEventstore(tt.expects...)(t),
				checkPermission:  permission,
				ownerDeleteReady: func(context.Context) (bool, error) { return true, nil },
			}
			got, err := r.MoveUser(ctx, "user1", tt.organizationID, nil, nil)
			if tt.wantErr != nil {
				assert.True(t, tt.wantErr(err), "unexpected error: %v", err)
				return
			}
			assert.NoError(t, err)
			assertObjectDetails(t, &domain.ObjectDetails{ResourceOwner: "org2"}, got)
		})
	}
}

// The removal must keep the user's current organization: otherwise the
// eventstore stamps it with the owner of the added event that follows it.
func TestCommandSide_MoveUserRemovalEnforcesCurrentOrganization(t *testing.T) {
	human := NewUserHumanWriteModel("user1", "org1", false, false, false, false, false, false, false)
	removal, err := (&Commands{}).moveUserRemoveEvent(context.Background(), human, true)
	assert.NoError(t, err)
	assert.True(t, eventstore.ShouldEnforceResourceOwner(removal))
	assert.Equal(t, "org1", removal.Aggregate().ResourceOwner)
	assert.Equal(t, user.UserRemovedType, removal.Type())
}
