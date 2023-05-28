package main

import (
	"log"
	"net/http"

	"github.com/sing3demons/go-fiber-auth-api/controllers"
	"github.com/sing3demons/go-fiber-auth-api/db"
	"github.com/sing3demons/go-fiber-auth-api/repository"
	routes "github.com/sing3demons/go-fiber-auth-api/router"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Println(err)
	}
}

func main() {
	conn := db.NewConnection()
	defer conn.Close()
	app := fiber.New()
	app.Use(cors.New())
	app.Use(logger.New())
	app.Get("/", func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{"message": "Hello World"})
	})

	usersRepo := repository.NewUsersRepository(conn)
	authController := controllers.NewAuthController(usersRepo)
	authRoutes := routes.NewAuthRoutes(authController)
	authRoutes.Install(app)

	log.Fatal(app.Listen(":8080"))
}
