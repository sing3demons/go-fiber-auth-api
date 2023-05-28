package routes

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/sing3demons/go-fiber-auth-api/security"
)

type Routes interface {
	Install(app *fiber.App)
}

func AuthRequired(ctx *fiber.Ctx) error {
	const BEARER_SCHEMA = "Bearer "

	authorization := ctx.Get("Authorization")
	tokenStr := strings.Split(authorization, BEARER_SCHEMA)[1]
	claims, err := security.ParseToken(tokenStr)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Unauthorized"})
	}

	fmt.Println(claims)

	sub, err := claims.GetSubject()
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Unauthorized"})
	}

	ctx.Locals("userId", sub)

	return ctx.Next()
}
