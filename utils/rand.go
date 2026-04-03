package utils

import (
	"crypto/rand"
	"math/big"
)

// RandString 生成随机字符串
func RandString(number int) string {
	if number <= 0 {
		return ""
	}
	str := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	randomString := make([]byte, number)
	max := big.NewInt(int64(len(str)))
	for i := 0; i < number; i++ {
		randomIndex, err := rand.Int(rand.Reader, max)
		if err != nil {
			// 极端情况下回退到固定字符，避免 panic
			randomString[i] = str[0]
			continue
		}
		randomString[i] = str[randomIndex.Int64()]
	}
	return string(randomString)
}
