package db

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type Connection interface {
	Close()
	DB() *mongo.Database
	InitDB() *mongo.Database
}

type conn struct {
	session *mongo.Client
}

func (c *conn) InitDB() *mongo.Database {
	port := os.Getenv("DATABASE_PORT")

	username := os.Getenv("DATABASE_USER")
	password := os.Getenv("DATABASE_PASS")
	host := os.Getenv("DATABASE_HOST")
	dbName := os.Getenv("DATABASE_NAME")
	uri := fmt.Sprintf("mongodb://%s:%s@%s:%s", username, password, host, port)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		panic(err)
	}
	fmt.Println("Connected to MongoDB!")

	db := client.Database(dbName)

	return db
}

func NewConnection() Connection {
	var c conn
	var err error

	dbName := os.Getenv("DATABASE_NAME")
	uri := getURL()
	fmt.Println(uri)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		panic(err)
	}

	c.session = client

	client.Database(dbName)

	fmt.Println("Connected to MongoDB!")
	return &c
}

func (c *conn) Close() {
	defer func() {
		if err := c.session.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()

}

func (c *conn) DB() *mongo.Database {
	return c.session.Database(os.Getenv("DATABASE_NAME"))
}

func getURL() string {
	port := os.Getenv("DATABASE_PORT")
	username := os.Getenv("DATABASE_USER")
	password := os.Getenv("DATABASE_PASS")
	host := os.Getenv("DATABASE_HOST")

	return fmt.Sprintf("mongodb://%s:%s@%s:%s", username, password, host, port)

}
