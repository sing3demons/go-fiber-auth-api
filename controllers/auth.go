package controllers

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"gopkg.in/asaskevich/govalidator.v9"

	"github.com/sing3demons/go-fiber-auth-api/models"
	"github.com/sing3demons/go-fiber-auth-api/repository"
	"github.com/sing3demons/go-fiber-auth-api/security"
	"github.com/sing3demons/go-fiber-auth-api/util"
)

type AuthController interface {
	SignUp(ctx *fiber.Ctx) error
	SignIn(ctx *fiber.Ctx) error
	GetUser(ctx *fiber.Ctx) error
	GetUsers(ctx *fiber.Ctx) error
	PutUser(ctx *fiber.Ctx) error
	DeleteUser(ctx *fiber.Ctx) error
}

type authController struct {
	usersRepo repository.UsersRepository
}

func NewAuthController(usersRepo repository.UsersRepository) AuthController {
	return &authController{usersRepo}
}

func (c *authController) SignUp(ctx *fiber.Ctx) error {
	var newUser models.User
	err := ctx.BodyParser(&newUser)
	if err != nil {
		return ctx.
			Status(http.StatusUnprocessableEntity).
			JSON(util.NewJError(err))
	}
	newUser.Email = util.NormalizeEmail(newUser.Email)

	if !govalidator.IsEmail(newUser.Email) {
		return ctx.
			Status(http.StatusBadRequest).
			JSON(util.NewJError(util.ErrInvalidEmail))
	}

	exists, err := c.usersRepo.GetByEmail(newUser.Email)

	if err != nil {
		if err != mongo.ErrNoDocuments {
			return ctx.Status(fiber.StatusBadRequest).JSON(util.NewJError(err))
		}
	}

	if exists != nil {
		return ctx.
			Status(http.StatusBadRequest).
			JSON(util.NewJError(util.ErrEmailAlreadyExists))
	}

	fmt.Println(newUser.Password)

	if strings.TrimSpace(newUser.Password) == "" {
		return ctx.
			Status(http.StatusBadRequest).
			JSON(util.NewJError(util.ErrEmptyPassword))
	}

	newUser.Password, err = security.EncryptPassword(newUser.Password)
	if err != nil {
		return ctx.
			Status(http.StatusBadRequest).
			JSON(util.NewJError(err))
	}
	newUser.CreatedAt = time.Now()
	newUser.UpdatedAt = newUser.CreatedAt
	newUser.Id = primitive.NewObjectID()
	err = c.usersRepo.Save(&newUser)
	if err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(util.NewJError(err))
	}

	return ctx.Status(http.StatusCreated).JSON(fiber.Map{
		"message": "User created successfully",
	})

}

func (c *authController) SignIn(ctx *fiber.Ctx) error {
	var input models.User
	err := ctx.BodyParser(&input)
	if err != nil {
		return ctx.
			Status(http.StatusUnprocessableEntity).
			JSON(util.NewJError(err))
	}
	input.Email = util.NormalizeEmail(input.Email)
	user, err := c.usersRepo.GetByEmail(input.Email)
	if err != nil {
		log.Printf("%s signin failed: %v\n", input.Email, err.Error())
		return ctx.
			Status(http.StatusUnauthorized).
			JSON(util.NewJError(util.ErrInvalidCredentials))
	}
	err = security.VerifyPassword(user.Password, input.Password)
	if err != nil {
		log.Printf("%s signin failed: %v\n", input.Email, err.Error())
		return ctx.
			Status(http.StatusUnauthorized).
			JSON(util.NewJError(util.ErrInvalidCredentials))
	}
	token, err := security.NewToken(user.Id.Hex())
	if err != nil {
		log.Printf("%s signin failed: %v\n", input.Email, err.Error())
		return ctx.
			Status(http.StatusUnauthorized).
			JSON(util.NewJError(err))
	}
	return ctx.
		Status(http.StatusOK).
		JSON(fiber.Map{
			"token": token,
		})
}

func (c *authController) GetUser(ctx *fiber.Ctx) error {
	payload, err := AuthRequestWithId(ctx)
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(util.NewJError(err))
	}
	user, err := c.usersRepo.GetById(payload.ID)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(util.NewJError(err))
	}

	return ctx.
		Status(http.StatusOK).
		JSON(user)
}

func (c *authController) GetUsers(ctx *fiber.Ctx) error {
	users, err := c.usersRepo.GetAll()
	if err != nil {
		return ctx.
			Status(http.StatusInternalServerError).
			JSON(util.NewJError(err))
	}
	return ctx.
		Status(http.StatusOK).
		JSON(users)
}

func (c *authController) PutUser(ctx *fiber.Ctx) error {
	payload, err := AuthRequestWithId(ctx)
	fmt.Println("++++++++++++")
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(util.NewJError(err))
	}
	var update models.User

	if err := ctx.BodyParser(&update); err != nil {

		return ctx.Status(http.StatusUnprocessableEntity).JSON(util.NewJError(err))
	}

	fmt.Println(update.Email)

	update.Email = util.NormalizeEmail(update.Email)
	if !govalidator.IsEmail(update.Email) {
		return ctx.Status(http.StatusBadRequest).JSON(util.NewJError(util.ErrInvalidEmail))
	}

	user, err := c.usersRepo.GetById(payload.ID)
	if err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(util.NewJError(err))
	}

	if user.Email == update.Email {
		return ctx.Status(http.StatusBadRequest).JSON(util.NewJError(util.ErrEmailAlreadyExists))
	}
	update.UpdatedAt = time.Now()
	err = c.usersRepo.Update(&update)
	fmt.Println(err)
	if err != nil {
		return ctx.Status(http.StatusUnprocessableEntity).JSON(util.NewJError(err))
	}

	return ctx.Status(http.StatusOK).JSON(user)
}

func (c *authController) DeleteUser(ctx *fiber.Ctx) error {
	payload, err := AuthRequestWithId(ctx)
	if err != nil {
		return ctx.
			Status(http.StatusUnauthorized).
			JSON(util.NewJError(err))
	}
	err = c.usersRepo.Delete(payload.ID)
	if err != nil {
		return ctx.
			Status(http.StatusInternalServerError).
			JSON(util.NewJError(err))
	}
	ctx.Set("Entity", payload.ID)
	return ctx.SendStatus(http.StatusNoContent)
}

func AuthRequestWithId(ctx *fiber.Ctx) (*jwt.RegisteredClaims, error) {
	id := ctx.Params("id")
	if !primitive.IsValidObjectID(id) {
		return nil, util.ErrUnauthorized
	}

	userId := ctx.Locals("userId")

	payload := &jwt.RegisteredClaims{
		ID: userId.(string),
	}

	if payload.ID != id {
		return nil, util.ErrUnauthorized
	}
	return payload, nil
}
