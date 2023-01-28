package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type Ccon struct {
	Username string
	Color    []string
}

var cuser []Ccon
var jwtKey = []byte("secret_key")
var users = map[string]string{
	"admin": "admin",
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Colorstr struct {
	Color string `json:"color"`
}
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Login(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	expectedPassword, ok := users[credentials.Username]
	if !ok || expectedPassword != credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	expirationTime := time.Now().Add(time.Hour * 24)
	claims := &Claims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
}
func Signup(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var credentials Credentials
		err := json.NewDecoder(r.Body).Decode(&credentials)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for key := range users {
			if credentials.Username == key {
				w.WriteHeader(http.StatusConflict)
				return
			}
		}
		users[credentials.Username] = credentials.Password
		cuser = append(cuser, Ccon{Username: credentials.Username, Color: []string{}})
		w.WriteHeader(http.StatusOK)
	} else {
		dat, err := os.ReadFile("./templates/sighup.html")
		if err != nil {
			fmt.Print(err)
		}
		w.Write([]byte(string(dat)))
	}
}
func Home(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("<h1>Login Required</h1>"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("<h1>Login Required</h1>"))
		return
	}
	tokenStr := cookie.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("<h1>Login Required</h1>"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("<h1>Login Required</h1>"))
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("<h1>Login Required</h1>"))
		return
	}
	if r.Method == "POST" {
		var color Colorstr
		err := json.NewDecoder(r.Body).Decode(&color)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for i := range cuser {
			if claims.Username == cuser[i].Username {
				cuser[i].Color = append(cuser[i].Color, color.Color)
				break
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	dat, err := os.ReadFile("./templates/home.html")
	if err != nil {
		fmt.Print(err)
	}
	w.Write([]byte(strings.Replace(string(dat), "claims.Username", claims.Username, -1)))
}
func Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tokenStr := cookie.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	expirationTime := time.Now().Add(time.Hour * 24)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w,
		&http.Cookie{
			Name:    "refresh_token",
			Value:   tokenString,
			Expires: expirationTime,
		})
}
func LoginPage(w http.ResponseWriter, r *http.Request) {
	dat, err := os.ReadFile("./templates/login.html")
	if err != nil {
		fmt.Print(err)
	}
	w.Write([]byte(string(dat)))
}
func gethostory(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("<h1>Login Required</h1>"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("<h1>Login Required</h1>"))
		return
	}
	tokenStr := cookie.Value
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("<h1>Login Required</h1>"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("<h1>Login Required</h1>"))
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("<h1>Login Required</h1>"))
		return
	}
	for i := range cuser {
		if claims.Username == cuser[i].Username {
			js, err := json.Marshal(cuser[i])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(js)
			break
		}
	}
}
func main() {
	cuser = append(cuser, Ccon{Username: "admin", Color: []string{"#ff0000", "#00ff00",
		"#0000ff"}})
	router := mux.NewRouter()
	router.HandleFunc("/", LoginPage).Methods("GET")
	router.HandleFunc("/login", Login).Methods("POST")
	router.HandleFunc("/signup", Signup).Methods("GET")
	router.HandleFunc("/signup", Signup).Methods("POST")
	router.HandleFunc("/home", Home).Methods("GET")
	router.HandleFunc("/home", Home).Methods("POST")
	router.HandleFunc("/refresh", Refresh).Methods("GET")
	router.HandleFunc("/gethostory", gethostory).Methods("GET")
	fmt.Println("Listening At - http://127.0.0.1:8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

// go mod init mod
// go get "github.com/gorilla/mux"
// go get "github.com/dgrijalva/jwt-go"
// go install github.com/dgrijalva/jwt-go@latest
// go install github.com/gorilla/mux@latest
// go mod tidy
