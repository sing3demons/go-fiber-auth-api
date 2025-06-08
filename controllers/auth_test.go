package controllers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/sing3demons/go-fiber-auth-api/models"
	"github.com/sing3demons/go-fiber-auth-api/repository"
	"github.com/sing3demons/go-fiber-auth-api/security"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func setupMockPostSignUp(body []byte, repoMock repository.UsersRepositoryMock) (*http.Response, error) {
	path := "/signup"
	authController := NewAuthController(&repoMock, security.NewSecurityToken())

	//
	app := fiber.New()
	app.Post(path, authController.SignUp)

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return app.Test(req)
}

// SignUp
func TestSignUp(t *testing.T) {
	t.Run("SignUp_Success", func(t *testing.T) {
		payload := models.User{
			Email:    "test@example.com",
			Password: "securepassword",
		}
		body, _ := json.Marshal(payload)

		resp, err := setupMockPostSignUp(body, repository.UsersRepositoryMock{})

		//
		assert.NoError(t, err)
		assert.Equal(t, 201, resp.StatusCode)
	})

	t.Run("BodyParser error", func(t *testing.T) {
		payload := "x"
		body, _ := json.Marshal(payload)

		//
		resp, err := setupMockPostSignUp(body, repository.UsersRepositoryMock{})

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	})

	t.Run("SignUp_InvalidEmail", func(t *testing.T) {
		payload := models.User{
			Email:    "invalid-email",
			Password: "securepassword",
		}
		body, _ := json.Marshal(payload)

		resp, err := setupMockPostSignUp(body, repository.UsersRepositoryMock{})

		//
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("SignUp_EmailAlreadyExists 1", func(t *testing.T) {
		payload := models.User{
			Email:    "test@example.com",
			Password: "securepassword",
		}
		body, _ := json.Marshal(payload)

		resp, err := setupMockPostSignUp(body, repository.UsersRepositoryMock{
			Err: errors.New("Email already exists"),
		})

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "Email already exists", responseBody["error"])
	})

	t.Run("SignUp_EmailAlreadyExists 2", func(t *testing.T) {
		payload := models.User{
			Email:    "test@example.com",
			Password: "securepassword",
		}
		body, _ := json.Marshal(payload)

		resp, err := setupMockPostSignUp(body, repository.UsersRepositoryMock{
			Err: mongo.ErrNoDocuments,
			Users: map[string]*models.User{
				"1234567890abcdef12345678": {Email: payload.Email},
			},
		})

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "email already exists", responseBody["error"])
	})

	t.Run("SignUp_EmptyPassword", func(t *testing.T) {
		payload := models.User{
			Email:    "test@example.com",
			Password: "",
		}

		body, _ := json.Marshal(payload)
		resp, err := setupMockPostSignUp(body, repository.UsersRepositoryMock{})
		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "password can't be empty", responseBody["error"])
	})

	t.Run("SignUp_EncryptPasswordError", func(t *testing.T) {
		payload := models.User{
			Email:    "test@example.com",
			Password: "secureC897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612C897E8FC-47B8-4DA9-A185-E4D780CA6612password",
		}
		body, _ := json.Marshal(payload)

		resp, err := setupMockPostSignUp(body, repository.UsersRepositoryMock{})
		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "bcrypt: password length exceeds 72 bytes", responseBody["error"])
	})

	t.Run("SignUp_SaveError", func(t *testing.T) {
		payload := models.User{
			Email:    "test@xxx.com",
			Password: "securepassword",
		}

		body, _ := json.Marshal(payload)
		resp, err := setupMockPostSignUp(body, repository.UsersRepositoryMock{})
		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "user cannot be nil", responseBody["error"])
	})

}

// SignIn
func setupMockPostSignIn(body []byte, repoMock repository.UsersRepositoryMock, sec security.SecurityToken) (*http.Response, error) {
	path := "/signin"
	authController := NewAuthController(&repoMock, sec)

	app := fiber.New()
	app.Post(path, authController.SignIn)

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return app.Test(req)
}

type mockSecurityToken struct {
	security.SecurityToken
	Err error
}

func (m *mockSecurityToken) NewToken(userId string) (string, error) {
	if m.Err != nil {
		return "", m.Err
	}
	claims := jwt.RegisteredClaims{
		ID:        userId,
		Issuer:    userId,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 30)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte("mock-secret-key"))
}

func TestSignIn(t *testing.T) {
	userId := primitive.NewObjectID()
	id := userId.Hex()
	mockPassword := "securepassword"
	mockEmail := "sing@dev.com"
	hashedPassword, _ := security.EncryptPassword(mockPassword)

	mockSecurity := security.NewSecurityToken()
	t.Run("SignIn_Success", func(t *testing.T) {
		payload := models.User{
			Email:    mockEmail,
			Password: mockPassword,
		}
		body, _ := json.Marshal(payload)

		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				id: {
					Email:    payload.Email,
					Password: hashedPassword,
					Id:       userId,
				},
			},
			Err: nil,
		}

		resp, err := setupMockPostSignIn(body, repoMock, mockSecurity)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var responseBody map[string]string
		err = json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.NoError(t, err)
		assert.NotEmpty(t, responseBody["token"])
	})

	t.Run("SignIn_BodyParser_Error", func(t *testing.T) {
		payload := "x"
		body, _ := json.Marshal(payload)

		resp, err := setupMockPostSignIn(body, repository.UsersRepositoryMock{}, mockSecurity)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)

		var responseBody map[string]string
		err = json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.NoError(t, err)
		assert.Equal(t, "json: cannot unmarshal string into Go value of type models.User", responseBody["error"])
	})

	t.Run("SignIn_GetByEmail_Error", func(t *testing.T) {
		payload := models.User{
			Email:    mockEmail,
			Password: mockPassword,
		}
		body, _ := json.Marshal(payload)

		repoMock := repository.UsersRepositoryMock{
			Err: errors.New("user not found"),
		}

		resp, err := setupMockPostSignIn(body, repoMock, mockSecurity)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var responseBody map[string]string
		err = json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.NoError(t, err)
		assert.Equal(t, "invalid credentials", responseBody["error"])
	})

	t.Run("SignIn_VerifyPassword_Error", func(t *testing.T) {
		payload := models.User{
			Email:    mockEmail,
			Password: "wrongpassword",
		}

		body, _ := json.Marshal(payload)
		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				id: {
					Email:    payload.Email,
					Password: hashedPassword,
					Id:       userId,
				},
			},
			Err: nil,
		}

		resp, err := setupMockPostSignIn(body, repoMock, mockSecurity)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var responseBody map[string]string
		err = json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.NoError(t, err)
		assert.Equal(t, "invalid credentials", responseBody["error"])
	})

	t.Run("SignIn_NewToken_Error", func(t *testing.T) {
		payload := models.User{
			Email:    mockEmail,
			Password: mockPassword,
		}

		body, _ := json.Marshal(payload)
		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				id: {
					Email:    payload.Email,
					Password: hashedPassword,
					Id:       userId,
				},
			},
			Err: nil,
		}

		mockSecurityErr := &mockSecurityToken{
			Err: errors.New("token creation failed"),
		}

		resp, err := setupMockPostSignIn(body, repoMock, mockSecurityErr)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		var responseBody map[string]string
		err = json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.NoError(t, err)
		assert.Equal(t, "token creation failed", responseBody["error"])
	})

}

func setupMockGetUser(userId string, handlers fiber.Handler, repoMock repository.UsersRepositoryMock) (*http.Response, error) {
	path := "/users/:id"
	authController := NewAuthController(&repoMock, security.NewSecurityToken())

	app := fiber.New()
	app.Get(path, handlers, authController.GetUser)

	req := httptest.NewRequest(http.MethodGet, strings.Replace(path, ":id", userId, 1), nil)
	req.Header.Set("Content-Type", "application/json")
	return app.Test(req)
}

func TestGetUser(t *testing.T) {
	t.Run("GetUser_Success", func(t *testing.T) {
		userId := primitive.NewObjectID().Hex()
		id, _ := primitive.ObjectIDFromHex(userId)
		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				userId: {
					Id:    id,
					Email: "test@ex.com",
				},
			},
		}

		resp, err := setupMockGetUser(userId, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)

			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var responseBody models.User
		err = json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.NoError(t, err)
		assert.Equal(t, userId, responseBody.Id.Hex())
	})

	t.Run("GetUser_InvalidId", func(t *testing.T) {
		userId := "invalid-id"
		repoMock := repository.UsersRepositoryMock{}

		resp, err := setupMockGetUser(userId, func(ctx *fiber.Ctx) error {
			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "Unauthorized", responseBody["error"])
	})

	t.Run("GetUser_id_not_match_param_id", func(t *testing.T) {
		userId := primitive.NewObjectID().Hex()
		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{},
		}

		resp, err := setupMockGetUser(userId, func(ctx *fiber.Ctx) error {
			ctx.Locals("userId", "xxx")

			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "Unauthorized", responseBody["error"])
	})

	t.Run("GetUser_NotFound", func(t *testing.T) {
		userId := primitive.NewObjectID().Hex()
		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{},
			Err:   errors.New("User not found"),
		}

		resp, err := setupMockGetUser(userId, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)

			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "User not found", responseBody["error"])
	})
}

func setupMockGetUsers(repoMock repository.UsersRepositoryMock) (*http.Response, error) {
	path := "/users"
	authController := NewAuthController(&repoMock, security.NewSecurityToken())

	app := fiber.New()
	app.Get(path, authController.GetUsers)

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Content-Type", "application/json")
	return app.Test(req)
}

func TestGetUsers(t *testing.T) {
	t.Run("GetUsers_Success", func(t *testing.T) {
		userId := primitive.NewObjectID()

		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				userId.Hex(): {Id: userId, Email: "test@test.com"},
			},
		}
		resp, err := setupMockGetUsers(repoMock)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var responseBody []models.User
		err = json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.NoError(t, err)
		assert.Len(t, responseBody, 1)
	})

	t.Run("GetUsers_Empty", func(t *testing.T) {
		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{},
			Err:   mongo.ErrNoDocuments,
		}
		resp, err := setupMockGetUsers(repoMock)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		var responseBody map[string]string
		err = json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.NoError(t, err)
		assert.Equal(t, "mongo: no documents in result", responseBody["error"])
	})
}

func setupMockDeleteUser(userId string, handlers fiber.Handler, repoMock repository.UsersRepositoryMock) (*http.Response, error) {
	path := "/users/:id"
	authController := NewAuthController(&repoMock, security.NewSecurityToken())

	app := fiber.New()
	app.Delete(path, handlers, authController.DeleteUser)

	req := httptest.NewRequest(http.MethodDelete, strings.Replace(path, ":id", userId, 1), nil)
	req.Header.Set("Content-Type", "application/json")
	return app.Test(req)
}

func TestDeleteUser(t *testing.T) {
	t.Run("DeleteUser_Success", func(t *testing.T) {
		userId := primitive.NewObjectID().Hex()
		id, _ := primitive.ObjectIDFromHex(userId)
		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				userId: {
					Id:    id,
					Email: "test@ex.com",
				},
			},
		}

		resp, err := setupMockDeleteUser(userId, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)

			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	})

	t.Run("DeleteUser_InvalidId", func(t *testing.T) {
		userId := "invalid-id"
		repoMock := repository.UsersRepositoryMock{}

		resp, err := setupMockDeleteUser(userId, func(ctx *fiber.Ctx) error {
			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "Unauthorized", responseBody["error"])
	})

	t.Run("DeleteUser_DeleteError", func(t *testing.T) {
		userId := primitive.NewObjectID().Hex()
		repoMock := repository.UsersRepositoryMock{
			Err: errors.New("user not found"),
		}

		resp, err := setupMockDeleteUser(userId, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)

			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "user not found", responseBody["error"])
	})
}

func setupMockUpdateUser(userId string, body []byte, handlers fiber.Handler, repoMock repository.UsersRepositoryMock) (*http.Response, error) {
	path := "/users/:id"
	authController := NewAuthController(&repoMock, security.NewSecurityToken())

	app := fiber.New()
	app.Put(path, handlers, authController.PutUser)

	req := httptest.NewRequest(http.MethodPut, strings.Replace(path, ":id", userId, 1), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return app.Test(req)
}

func TestUpdateUser(t *testing.T) {
	mockEmail := "sing@dev.com"
	userId := primitive.NewObjectID().Hex()
	id, _ := primitive.ObjectIDFromHex(userId)

	t.Run("UpdateUser_Success", func(t *testing.T) {
		payload := models.User{
			Id:    id,
			Email: mockEmail,
		}
		body, _ := json.Marshal(payload)

		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				userId: {
					Id:    id,
					Email: "sing@2dev.com",
				},
			},
			Err: nil,
		}
		resp, err := setupMockUpdateUser(userId, body, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)

			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var responseBody models.User
		err = json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.NoError(t, err)
		assert.Equal(t, userId, responseBody.Id.Hex())
		assert.Equal(t,  "sing@2dev.com", responseBody.Email)
	})

	t.Run("UpdateUser_InvalidId", func(t *testing.T) {
		payload := models.User{
			Id:    id,
			Email: mockEmail,
		}
		body, _ := json.Marshal(payload)
		repoMock := repository.UsersRepositoryMock{}
		resp, err := setupMockUpdateUser("xx", body, func(ctx *fiber.Ctx) error {
			return ctx.Next()
		}, repoMock)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "Unauthorized", responseBody["error"])
	})

	t.Run("UpdateUser_BodyParser_Error", func(t *testing.T) {
		payload := "x"
		body, _ := json.Marshal(payload)

		repoMock := repository.UsersRepositoryMock{}
		resp, err := setupMockUpdateUser(userId, body, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)
			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "json: cannot unmarshal string into Go value of type models.User", responseBody["error"])
	})

	t.Run("UpdateUser_InvalidEmail", func(t *testing.T) {
		payload := models.User{
			Id:    id,
			Email: "invalid-email",
		}
		body, _ := json.Marshal(payload)

		repoMock := repository.UsersRepositoryMock{}
		resp, err := setupMockUpdateUser(userId, body, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)
			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "invalid email", responseBody["error"])
	})

	t.Run("UpdateUser_EmailAlreadyExists", func(t *testing.T) {
		payload := models.User{
			Id:    id,
			Email: mockEmail,
		}
		body, _ := json.Marshal(payload)

		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				userId: {
					Id:    id,
					Email: mockEmail,
				},
			},
			Err: errors.New("email already exists"),
		}

		resp, err := setupMockUpdateUser(userId, body, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)

			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "email already exists", responseBody["error"])
	})

	t.Run("UpdateUser_UpdateError email already exists", func(t *testing.T) {
		payload := models.User{
			Id:    id,
			Email: mockEmail,
		}
		body, _ := json.Marshal(payload)

		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				userId: {
					Id:    id,
					Email: mockEmail,
				},
			},
		}

		resp, err := setupMockUpdateUser(userId, body, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)

			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "email already exists", responseBody["error"])
	})

	t.Run("UpdateUser_UpdateError", func(t *testing.T) {
		payload := models.User{
			Id:    id,
			Email:  "test@xxx.com",
		}

		body, _ := json.Marshal(payload)
		repoMock := repository.UsersRepositoryMock{
			Users: map[string]*models.User{
				userId: {
					Id:    id,
					Email:mockEmail,
				},
			},
		}

		resp, err := setupMockUpdateUser(userId, body, func(ctx *fiber.Ctx) error {
			payload := &jwt.RegisteredClaims{
				ID: userId,
			}
			ctx.Locals("userId", payload.ID)

			return ctx.Next()
		}, repoMock)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
		var responseBody map[string]string
		json.NewDecoder(resp.Body).Decode(&responseBody)
		assert.Equal(t, "user cannot be nil", responseBody["error"])
	})

}
