package main

import (
	"ServiceJWT/internal/jwt"
	"ServiceJWT/internal/postgre"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

//TIP To run your code, right-click the code and select <b>Run</b>. Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.

func main() {
	//TIP Press <shortcut actionId="ShowIntentionActions"/> when your caret is at the underlined or highlighted text
	// to see how GoLand suggests fixing it.

	http.HandleFunc("/sign-in", signIn)
	http.HandleFunc("/refresh-token", refreshToken)
	checkAuthHandler := http.HandlerFunc(checkAuth)
	http.Handle("/check-auth", jwt.AuthMiddleware(checkAuthHandler))

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		return
	}
}

func checkAuth(writer http.ResponseWriter, request *http.Request) {
	writer.Write([]byte("Аутентификация прошла успешно!"))
}

func refreshToken(writer http.ResponseWriter, request *http.Request) {
	var clientIP = strings.Split(request.RemoteAddr, ":")[0]

	params, _ := url.ParseQuery(request.URL.RawQuery)
	var rt = fmt.Sprint(params["refresh_token"])
	rt = strings.Replace(rt, "[", "", 1)
	rt = strings.Replace(rt, "]", "", 1)

	token, err := jwt.VerifyToken(rt)
	if err != nil {
		writer.WriteHeader(http.StatusUnauthorized)
		writer.Write([]byte(fmt.Sprintf("Token verification failed: %v\n", err)))
		return
	}
	// Print information about the verified token
	subjectId, _ := token.Claims.GetSubject()

	if rt != "" && postgre.ValidateRefreshToken(rt, subjectId) {

		// Print information about the verified token
		jwtIP, _ := token.Claims.GetAudience()

		if clientIP != jwtIP[0] {
			slog.Warn("Сменился адрес устойства")
			// TODO Отправка email warning на почту юзера
		}

		id, _ := uuid.Parse(subjectId)
		JWT := jwt.GetTokenPair(id, clientIP)
		jsonJWT, _ := json.Marshal(JWT)

		postgre.LoginOrRegister(id, JWT)
		fmt.Fprintf(writer, string(jsonJWT))

	} else {
		writer.WriteHeader(http.StatusUnauthorized)
	}
}

func signIn(writer http.ResponseWriter, request *http.Request) {
	// Получаемый IP-адрес устройства, с которого пришёл запрос
	var clientIP = strings.Split(request.RemoteAddr, ":")[0]

	params, _ := url.ParseQuery(request.URL.RawQuery)
	var id, _ = uuid.Parse(fmt.Sprint(params["id"]))

	JWT := jwt.GetTokenPair(id, clientIP)
	jsonJWT, _ := json.Marshal(JWT)

	postgre.LoginOrRegister(id, JWT)
	fmt.Fprintf(writer, string(jsonJWT))

}
