package jwt_test

import (
	"github.com/gin-gonic/gin"
	jwt "github.com/langomobiledev/gin-jwt-cognito"
)

func ExampleAuthMiddleware() {

	// Creates a gin router with default middleware:
	router := gin.Default()

	// Create Cognito JWT auth middleware and set it  in all authenticated endpoints
	var jwk map[string]jwt.JWKKey
	mw, err := jwt.AuthJWTMiddleware("<some_iss>", "<some_userpool_id>", "region", jwk)
	if err != nil {
		panic(err)
	}

	router.GET("/someGet", mw.MiddlewareFunc(), func(context *gin.Context) {
		// some implementation
	})
	router.POST("/somePost", mw.MiddlewareFunc(), func(context *gin.Context) {
		// some implementation
	})
	router.PUT("/somePut", mw.MiddlewareFunc(), func(context *gin.Context) {
		// some implementation
	})

	// By default it serves on :8080 unless a
	// PORT environment variable was defined.
	router.Run()
}
