package postgre

import (
	"ServiceJWT/internal/entity"
	"ServiceJWT/internal/jwt"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
)

const (
	selectCmd = iota
	insertCmd
	updateCmd
)

func dbCommand(command string, cmdType int) interface{} {
	connStr := "user=postgres password=SecretPassword dbname=Golang.JWT-Service sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	switch cmdType {
	case selectCmd:
		rows, err := db.Query(command)
		if err != nil {
			panic(err)
		}
		defer rows.Close()

		for rows.Next() {
			user := entity.User{}
			err := rows.Scan(&user.Id, &user.RefreshToken)
			if err != nil {
				slog.Warn(err.Error())
				continue
			}
			return user
		}
		slog.Info("selectCmd", command)

	case insertCmd:
		result, err := db.Exec(command)
		if err != nil {
			panic(err)
		}
		slog.Info("insertCmd", result)

	case updateCmd:
		result, err := db.Exec(command)
		if err != nil {
			panic(err)
		}
		slog.Info("updateCmd", result)
	}

	return nil
}

func LoginOrRegister(userID uuid.UUID, jwt jwt.JWT) {
	var cmd = fmt.Sprintf("select * from users where id_user = '%s' LIMIT 1", userID)
	var userI = dbCommand(cmd, selectCmd)

	rt := []byte(jwt.Refresh_token)
	cost := 10
	refreshToken := sha256.New()
	refreshToken.Write(rt)

	hash, err := bcrypt.GenerateFromPassword(refreshToken.Sum(nil), cost)
	if err != nil {
		slog.Warn(err.Error())
	}
	if userI != nil {
		cmd = fmt.Sprintf("update users set refresh_token = '%s' where id_user = '%s'", hash, userID)
		dbCommand(cmd, updateCmd)
	} else {
		cmd = fmt.Sprintf("INSERT INTO public.users (id_user, refresh_token) VALUES ('%s', '%s')\n", userID, hash)
		dbCommand(cmd, insertCmd)
	}
}

func ValidateRefreshToken(refreshToken string, id string) bool {
	rt := []byte(refreshToken)
	refreshTokenHash := sha256.New()
	refreshTokenHash.Write(rt)
	refreshTokenHashSum := fmt.Sprintf("%s", refreshTokenHash.Sum(nil))

	var cmd = fmt.Sprintf("select * from users where id_user = '%s' LIMIT 1", id)
	var res = dbCommand(cmd, selectCmd)
	if res != nil {
		user := res.(entity.User)
		err := bcrypt.CompareHashAndPassword([]byte(user.RefreshToken), []byte(refreshTokenHashSum))
		if err == nil {
			return true
		}
		slog.Warn(err.Error())
	}
	return false
}

func RefreshToken(refresh_token string, jwt jwt.JWT) {
	var cmd = fmt.Sprintf("select * from users where refresh_token = '%s' LIMIT 1", refresh_token)
	var userI = dbCommand(cmd, selectCmd)
	if userI == nil {
		return
	}
	var user = userI.(*entity.User)

	rt := []byte(jwt.Refresh_token)
	cost := 10
	refreshToken := sha256.New()
	refreshToken.Write(rt)
	hash, err := bcrypt.GenerateFromPassword(refreshToken.Sum(nil), cost)
	if err != nil {
		slog.Warn(err.Error())
	}
	cmd = fmt.Sprintf("update users set refresh_token = '%s' where id_user = '%s'", hash, user.Id)
	dbCommand(cmd, updateCmd)
}
