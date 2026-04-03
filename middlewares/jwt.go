package middlewares

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sublink/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// GetJWTSecret 从配置文件读取JWT密钥（每次调用时读取，避免运行期配置更新后密钥不生效）
func GetJWTSecret() []byte {
	return []byte(models.ReadConfig().JwtSecret)
}

// JwtClaims jwt声明
type JwtClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// AuthorToken 验证token中间件
func AuthorToken(c *gin.Context) {
	// 定义白名单
	list := []string{"/static", "/api/v1/auth/login", "/api/v1/auth/captcha", "/c/", "/api/v1/version"}
	// 如果是首页直接跳过
	if c.Request.URL.Path == "/" {
		c.Next()
		return
	}
	// 如果是白名单直接跳过
	for _, v := range list {
		if strings.HasPrefix(c.Request.URL.Path, v) {
			c.Next()
			return
		}
	}
	authHeader := strings.TrimSpace(c.Request.Header.Get("Authorization"))
	if authHeader == "" {
		c.JSON(400, gin.H{"msg": "请求未携带token"})
		c.Abort()
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		c.JSON(400, gin.H{"msg": "token格式错误"})
		c.Abort()
		return
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		c.JSON(400, gin.H{"msg": "token格式错误"})
		c.Abort()
		return
	}
	mc, err := ParseToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code": 401,
			"msg":  err.Error(),
		})
		c.Abort()
		return
	}
	c.Set("username", mc.Username)
	c.Next()
}

func extractToken(authHeader string) string {
	token := strings.TrimSpace(authHeader)
	if len(token) >= 7 && strings.EqualFold(token[:7], "Bearer ") {
		token = strings.TrimSpace(token[7:])
	}
	return token
}

// ParseToken 解析JWT
func ParseToken(tokenString string) (*JwtClaims, error) {
	// 解析token
	token, err := jwt.ParseWithClaims(tokenString, &JwtClaims{}, func(token *jwt.Token) (i interface{}, err error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return GetJWTSecret(), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*JwtClaims); ok && token.Valid { // 校验token
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
