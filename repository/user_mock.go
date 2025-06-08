package repository

import (
	"errors"

	"github.com/sing3demons/go-fiber-auth-api/models"
)

type UsersRepositoryMock struct {
	Users map[string]*models.User
	Err   error
}

func (r *UsersRepositoryMock) Save(user *models.User) error {
	if r.Err != nil {
		return r.Err
	}
	if r.Users == nil {
		r.Users = make(map[string]*models.User)
	}

	if user.Email == "test@xxx.com" {
		return errors.New("user cannot be nil")
	}
	r.Users[user.Id.Hex()] = user
	return nil
}

func (r *UsersRepositoryMock) Update(user *models.User) error {
	if r.Err != nil {
		return r.Err
	}
	if r.Users == nil {
		return nil
	}

	if user.Email == "test@xxx.com" {
		return errors.New("user cannot be nil")
	}
	if _, exists := r.Users[user.Id.Hex()]; !exists {
		return nil
	}

	r.Users[user.Id.Hex()] = user
	return nil
}

func (r *UsersRepositoryMock) GetById(id string) (user *models.User, err error) {
	if r.Err != nil {
		return nil, r.Err
	}
	if r.Users == nil {
		return nil, nil
	}
	user, exists := r.Users[id]
	if !exists {
		return nil, nil
	}
	return user, nil
}

func (r *UsersRepositoryMock) GetByEmail(email string) (user *models.User, err error) {
	if r.Err != nil {
		if r.Users != nil {
			for _, u := range r.Users {
				if u.Email == email {
					user = u
					break
				}
			}
		}

		return user, r.Err
	}
	if r.Users == nil {
		return nil, nil
	}
	for _, u := range r.Users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, nil
}

func (r *UsersRepositoryMock) GetAll() (users []*models.User, err error) {
	if r.Err != nil {
		return nil, r.Err
	}
	if r.Users == nil {
		return nil, nil
	}
	for _, u := range r.Users {
		users = append(users, u)
	}
	return users, nil
}

func (r *UsersRepositoryMock) Delete(id string) error {
	if r.Err != nil {
		return r.Err
	}
	if r.Users == nil {
		return nil
	}
	if _, exists := r.Users[id]; !exists {
		return nil
	}
	delete(r.Users, id)
	return nil
}
