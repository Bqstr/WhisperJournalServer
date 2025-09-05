package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	// Important: side-effect import to enable pure-Go sqlite driver
	_ "modernc.org/sqlite"
)

// ================== MODELS ==================
type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"unique"`
	Password string
}

type Item struct {
	ID    uint `gorm:"primaryKey"`
	Name  string
	Value string
}

type Audio struct {
	ID         uint `gorm:"primaryKey"`
	Filename   string
	Path       string
	UploadedAt time.Time
}

// ================== JWT CONFIG ==================
var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// ================== GLOBAL DB ==================
var db *gorm.DB

func main() {
	var err error

	// ✅ Use pure Go sqlite driver
	db, err = gorm.Open(sqlite.Open("identifier.sqlite"), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// AutoMigrate schema
	db.AutoMigrate(&User{}, &Item{})

	r := gin.Default()

	r.GET("/public/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong from public"})
	})

	// Auth routes
	r.POST("/register", register)
	r.POST("/login", login)

	// CRUD routes (protected)
	authorized := r.Group("/")
	authorized.Use(AuthMiddleware())
	{
		authorized.GET("/items", getItems)
		authorized.POST("/items", createItem)
		authorized.PUT("/items/:id", updateItem)
		authorized.DELETE("/items/:id", deleteItem)
		authorized.POST("/upload", uploadMedia)
	}

	log.Println("🚀 Server started on :8080")
	r.Run(":8080")
}

// ================== HANDLERS ==================
func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username already exists"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "user registered"})
}

func login(c *gin.Context) {
	var input User
	var user User
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := db.Where("username = ? AND password = ?", input.Username, input.Password).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func getItems(c *gin.Context) {
	var items []Item
	db.Find(&items)
	c.JSON(http.StatusOK, items)
}

func createItem(c *gin.Context) {
	var item Item
	if err := c.ShouldBindJSON(&item); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	db.Create(&item)
	c.JSON(http.StatusOK, item)
}

func updateItem(c *gin.Context) {
	var item Item
	if err := db.First(&item, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "item not found"})
		return
	}
	if err := c.ShouldBindJSON(&item); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	db.Save(&item)
	c.JSON(http.StatusOK, item)
}

func deleteItem(c *gin.Context) {
	var item Item
	if err := db.Delete(&item, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "item not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "item deleted"})
}

// ================== MODELS ==================
type Media struct {
	ID         uint `gorm:"primaryKey"`
	Filename   string
	Path       string
	UploadedAt time.Time
}

// ================== HANDLER ==================
func uploadMedia(c *gin.Context) {
	// Get uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}

	// Save to "uploads/" folder
	uploadPath := "uploads/" + file.Filename
	if err := c.SaveUploadedFile(file, uploadPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save file"})
		return
	}

	// Save record in DB
	media := Media{
		Filename:   file.Filename,
		Path:       uploadPath,
		UploadedAt: time.Now(),
	}
	db.Create(&media)

	c.JSON(http.StatusOK, gin.H{
		"message":  "file uploaded successfully",
		"filename": file.Filename,
		"url":      "/uploads/" + file.Filename,
	})
}

// ================== MIDDLEWARE ==================
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}
