package models

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type UserModelInterface interface {
	Insert(name, email, password string) error
	Authenticate(email, password string) (int, error)
	Exists(id int) (bool, error)
	Retrieve(id int) (*User, error)
	ChangePassword(id int, password string, newpassword string) error
}

type User struct {
	ID             int
	Name           string
	Email          string
	HashedPassword []byte
	Created        time.Time
}

type UserModel struct {
	DB *sql.DB
}

func (m *UserModel) Insert(name, email, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}

	stmt := `INSERT INTO users (name, email, hashed_password, created)
	VALUES(?,?,?,UTC_TIMESTAMP())`

	_, err = m.DB.Exec(stmt, name, email, string(hashedPassword))
	if err != nil {
		var mySQLError *mysql.MySQLError
		if errors.As(err, &mySQLError) {
			if mySQLError.Number == 1062 && strings.Contains(mySQLError.Message, "users_uc_email") {
				return ErrDuplicateEmail
			}
		}
		return err
	}
	return nil

}

func (m *UserModel) Authenticate(email, password string) (int, error) {
	var id int
	var hashedPassword []byte
	stmt := "SELECT id, hashed_password FROM users WHERE email = ?"

	err := m.DB.QueryRow(stmt, email).Scan(&id, &hashedPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrInvvalidCredentials
		} else {
			return 0, err
		}
	}

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return 0, ErrInvvalidCredentials
		} else {
			return 0, err
		}
	}
	return id, nil
}

func (m *UserModel) Exists(id int) (bool, error) {
	var exists bool
	stmt := `SELECT EXISTS(SELECT true FROM users WHERE id = ?)`

	err := m.DB.QueryRow(stmt, id).Scan(&exists)

	return exists, err
}

func (m *UserModel) Retrieve(id int) (*User, error) {
	stmt := `SELECT name, email, created FROM users WHERE id = ?`

	row := m.DB.QueryRow(stmt, id)

	user := &User{}

	err := row.Scan(&user.Name, &user.Email, &user.Created)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoRecord
		} else {
			return nil, err
		}
	}

	return user, nil
}

func (m *UserModel) ChangePassword(id int, password, newpassword string) error {
	stmt1 := `SELECT hashed_password FROM users WHERE id = ?`
	var oldPassword string

	row := m.DB.QueryRow(stmt1, id)

	err := row.Scan(&oldPassword)

	fmt.Println(oldPassword)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoRecord

		} else {
			return err
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(oldPassword), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvvalidCredentials
		} else {
			return err
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newpassword), 12)
	if err != nil {
		return err
	}
	stmt := "UPDATE users SET hashed_password =  ? WHERE id = ?"

	_, err = m.DB.Exec(stmt, hashedPassword, id)

	if err != nil {
		return err
	}
	return nil
}
