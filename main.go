package main

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var jwtkey = []byte("my-secret-key")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Dbconnect() (*sql.DB, error) {
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1)/Dbconnect")
	if err != nil {
		return nil, err
	}
	return db, nil
}

func Signup(c *gin.Context) {
	var cred Credentials
	if err := c.BindJSON(&cred); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if cred.Username == "" || cred.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing username or password"})
		return
	}

	db, err := Dbconnect()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection error"})
		return
	}
	defer db.Close()

	var existingUser string
	err = db.QueryRow("SELECT username FROM users WHERE username =?", cred.Username).Scan(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cred.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
		return
	}

	_, err = db.Exec("INSERT INTO users(username, password) VALUES(?,?)", cred.Username, hashedPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"Message": "User created"})
}

func Signin(c *gin.Context) {
	var cred Credentials
	if err := c.BindJSON(&cred); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	db, err := Dbconnect()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection error"})
		return
	}
	defer db.Close()

	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username=?", cred.Username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Server error"})
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(cred.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Password"})
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: cred.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtkey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Server error"})
		return
	}

	c.SetCookie("token", tokenString, int(expirationTime.Sub(time.Now()).Seconds()), "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Signin successful"})
}

func Logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

func main() {
	router := gin.Default()

	router.POST("/signup", Signup)
	router.POST("/signin", Signin)
	router.POST("/logout", Logout)

	router.Run(":8080")
}
