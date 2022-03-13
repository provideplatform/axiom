package common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/provide-go/api/ident"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

// PanicIfEmpty panics if the given string is empty
func PanicIfEmpty(val string, msg string) {
	if val == "" {
		panic(msg)
	}
}

// RefreshPublicWorkgroupAccessToken is a convenience function to authorize a new access token
func RefreshPublicWorkgroupAccessToken() (*string, error) {
	token, err := ident.CreateToken(*BaselinePublicWorkgroupRefreshToken, map[string]interface{}{
		"grant_type": "refresh_token",
	})

	if err != nil {
		common.Log.Warningf("failed to authorize access token for given public workgroup refresh token; %s", err.Error())
		return nil, err
	}

	if token.AccessToken == nil {
		err := fmt.Errorf("failed to authorize access token for given public workgroup refresh token: %s", token.ID.String())
		common.Log.Warning(err.Error())
		return nil, err
	}

	return token.AccessToken, nil
}

// StringFromInterface returns the string representation of val, if val
// is in fact a string (or *string)
func StringFromInterface(val interface{}) *string {
	if val == nil {
		return nil
	}
	if str, ok := val.(string); ok {
		return &str
	}
	if strptr, ok := val.(*string); ok {
		return strptr
	}
	if arr, ok := val.([]byte); ok {
		return StringOrNil(string(arr))
	}
	return nil
}

// StringOrNil returns the given string or nil when empty
func StringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}

// RandomString generates a random string of the given length
func RandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// SHA256 is a convenience method to return the sha256 hash of the given input
func SHA256(str string) string {
	digest := sha256.New()
	digest.Write([]byte(str))
	return hex.EncodeToString(digest.Sum(nil))
}

func ParseIntFromString(str string) (uint64, error) {
	re := regexp.MustCompile("[0-9]+")
	strArr := re.FindAllString(str, -1)
	intStr := strings.Join(strArr, "")
	int, err := strconv.Atoi(intStr)
	return uint64(int), err
}
