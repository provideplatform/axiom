package baseline

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/kthomas/go-pgputil"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/provide-go/api/vault"
	"golang.org/x/crypto/ssh"
)

const defaultCredentialExperationTimeout = time.Hour * 1

// IssueVC vends a verifiable credential for the given third-party; it assumes authorization
// has already been completed successfully for the counterparty
func IssueVC(address string, params map[string]interface{}) (*string, error) {
	token, err := vendOrganizationAccessToken()
	if err != nil {
		common.Log.Warningf("failed to request verifiable credential for baseline organization: %s; %s", address, err.Error())
		return nil, err
	}

	keys, err := vault.ListKeys(*token, common.Vault.ID.String(), map[string]interface{}{
		"spec": "RSA-4096",
	})
	if err != nil {
		common.Log.Warningf("failed to resolve RSA-4096 key for organization; %s", err.Error())
		return nil, err
	}
	if len(keys) == 0 {
		common.Log.Warningf("failed to resolve RSA-4096 key for organization")
		return nil, errors.New("failed to resolve RSA-4096 key for organization")
	}
	key := keys[0]

	issuedAt := time.Now()

	claims := map[string]interface{}{
		"aud":      common.OrganizationMessagingEndpoint,
		"exp":      issuedAt.Add(defaultCredentialExperationTimeout).Unix(),
		"iat":      issuedAt.Unix(),
		"iss":      fmt.Sprintf("organization:%s", *common.OrganizationID),
		"sub":      address,
		"baseline": params,
	}

	natsClaims, err := encodeJWTNatsClaims()
	if err != nil {
		log.Printf("failed to encode NATS claims in JWT; %s", err.Error())
		os.Exit(1)
	}
	if natsClaims != nil {
		claims["nats"] = natsClaims
	}

	publicKey, err := pgputil.DecodeRSAPublicKeyFromPEM([]byte(*key.PublicKey))
	if err != nil {
		log.Printf("failed to decode RSA public key from PEM; %s", err.Error())
		os.Exit(1)
	}

	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		log.Printf("failed to decode SSH public key for fingerprinting; %s", err.Error())
		os.Exit(1)
	}
	fingerprint := ssh.FingerprintLegacyMD5(sshPublicKey)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	jwtToken.Header["kid"] = fingerprint

	strToSign, err := jwtToken.SigningString()
	if err != nil {
		log.Printf("failed to generate JWT string for signing; %s", err.Error())
		os.Exit(1)
	}

	opts := map[string]interface{}{}
	if strings.HasPrefix(*key.Spec, "RSA-") {
		opts["algorithm"] = "RS256"
	}

	resp, err := vault.SignMessage(
		*token,
		key.VaultID.String(),
		key.ID.String(),
		hex.EncodeToString([]byte(strToSign)),
		opts,
	)
	if err != nil {
		common.Log.Warningf("WARNING: failed to sign JWT using vault key: %s; %s", key.ID, err.Error())
		return nil, err
	}

	sigAsBytes, err := hex.DecodeString(*resp.Signature)
	if err != nil {
		log.Printf("failed to decode signature from hex; %s", err.Error())
		os.Exit(1)
	}

	encodedSignature := strings.TrimRight(base64.URLEncoding.EncodeToString(sigAsBytes), "=")
	return common.StringOrNil(strings.Join([]string{strToSign, encodedSignature}, ".")), nil
}

func encodeJWTNatsClaims() (map[string]interface{}, error) {
	publishAllow := make([]string, 0)
	publishDeny := make([]string, 0)

	subscribeAllow := make([]string, 0)
	subscribeDeny := make([]string, 0)

	var responsesMax *int
	var responsesTTL *time.Duration

	// subscribeAllow = append(subscribeAllow, "baseline.>")
	publishAllow = append(publishAllow, "baseline")
	publishAllow = append(publishAllow, "baseline.>")

	var publishPermissions map[string]interface{}
	if len(publishAllow) > 0 || len(publishDeny) > 0 {
		publishPermissions = map[string]interface{}{}
		if len(publishAllow) > 0 {
			publishPermissions["allow"] = publishAllow
		}
		if len(publishDeny) > 0 {
			publishPermissions["deny"] = publishDeny
		}
	}

	var subscribePermissions map[string]interface{}
	if len(subscribeAllow) > 0 || len(subscribeDeny) > 0 {
		subscribePermissions = map[string]interface{}{}
		if len(subscribeAllow) > 0 {
			subscribePermissions["allow"] = subscribeAllow
		}
		if len(subscribeDeny) > 0 {
			subscribePermissions["deny"] = subscribeDeny
		}
	}

	var responsesPermissions map[string]interface{}
	if responsesMax != nil || responsesTTL != nil {
		responsesPermissions = map[string]interface{}{}
		if responsesMax != nil {
			responsesPermissions["max"] = responsesMax
		}
		if responsesTTL != nil {
			responsesPermissions["ttl"] = responsesTTL
		}
	}

	var permissions map[string]interface{}
	if publishPermissions != nil || subscribePermissions != nil || responsesPermissions != nil {
		permissions = map[string]interface{}{}
		if publishPermissions != nil {
			permissions["publish"] = publishPermissions
		}
		if subscribePermissions != nil {
			permissions["subscribe"] = subscribePermissions
		}
		if responsesPermissions != nil {
			permissions["responses"] = responsesPermissions
		}
	}

	var natsClaims map[string]interface{}
	if permissions != nil {
		natsClaims = map[string]interface{}{
			"permissions": permissions,
		}
	}

	return natsClaims, nil
}
