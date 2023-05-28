package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/sing3demons/go-fiber-auth-api/db"
	"github.com/sing3demons/go-fiber-auth-api/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

const UsersCollection = "users"

type UsersRepository interface {
	Save(user *models.User) error
	Update(user *models.User) error
	GetById(id string) (user *models.User, err error)
	GetByEmail(email string) (user *models.User, err error)
	GetAll() (users []*models.User, err error)
	Delete(id string) error
}

type usersRepository struct {
	c *mongo.Collection
}

func NewUsersRepository(conn db.Connection) UsersRepository {
	return &usersRepository{
		c: conn.DB().Collection(UsersCollection),
	}
}

func (r *usersRepository) Save(user *models.User) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := r.c.InsertOne(ctx, user)
	if err != nil {
		return err
	}

	return nil
}

func (r *usersRepository) Update(user *models.User) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println(user)

	if _, err := r.c.UpdateByID(ctx, user.Id, user); err != nil {
		return err
	}
	return nil
}

func (r *usersRepository) GetById(id string) (user *models.User, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	if err := r.c.FindOne(ctx, bson.M{"_id": objectID}).Decode(&user); err != nil {
		return nil, err
	}
	return user, err
}

func (r *usersRepository) GetByEmail(email string) (user *models.User, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = r.c.FindOne(ctx, bson.M{"email": email}).Decode(&user)

	if err != nil {
		return nil, err
	}

	return user, err
}

func (r *usersRepository) GetAll() (users []*models.User, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cur, err := r.c.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}

	for cur.Next(ctx) {
		var user models.User
		if err := cur.Decode(&user); err != nil {
			return nil, err
		}
		users = append(users, &user)
	}

	return users, err
}

func (r *usersRepository) Delete(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	_, err = r.c.DeleteOne(ctx, bson.M{"_id": objectID})
	if err != nil {
		return err
	}
	return nil
}
