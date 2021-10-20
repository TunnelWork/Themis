package themis

// AuthBody.go provides a relatively simple design for the major informative part of an auth token which includes important authentication info.

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	hc "github.com/TunnelWork/Harpocrates"
)

const (
	sepAuthFactor string = "~"
)

var (
	ErrBadBase64Token error = errors.New("themis: bad base64 token")
	ErrIllformedBody  error = errors.New("themis: auth body is illformed")
	ErrBadIpAddr      error = errors.New("themis: cannot parse ip address")
)

type AuthBody struct {
	Identity     uint32
	IpAddr       net.IP
	Expiry       time.Time
	RevocationID uint32
}

func NewAuthBody(authedIdentity uint32, authedIP net.IP, revID uint32, validFor time.Duration) AuthBody {
	return AuthBody{
		Identity:     authedIdentity,
		IpAddr:       authedIP,
		RevocationID: revID,
		Expiry:       time.Now().Add(validFor),
	}
}

func AuthBodyFromBase64(b64token string) (AuthBody, error) {
	var ab = AuthBody{}
	var err error
	var tokenIdentity uint32
	var tokenIpAddr net.IP
	var tokenExpiry time.Time
	var tokenRevocationID uint32

	decodeToken := hc.Base64Decoding(b64token)
	if decodeToken == "" {
		return ab, ErrBadBase64Token
	}

	// Split & Parse
	authBodySplit := strings.Split(decodeToken, sepAuthFactor)
	if len(authBodySplit) != 4 { // If not 4 parts, token is incomplete
		return ab, ErrIllformedBody
	}

	// Parse identity
	tokenIdentity64, err := strconv.ParseUint(authBodySplit[0], 16, 32) // base: 16, size: 32-bit
	if err != nil {
		return ab, err
	}
	tokenIdentity = uint32(tokenIdentity64)

	// Parse ipAddr
	tokenIpAddr = net.ParseIP(authBodySplit[1])
	if tokenIpAddr == nil {
		return ab, ErrBadIpAddr
	}

	// Parse revocationID
	if len(authBodySplit[2]) > 0 {
		tokenRevocationID64, err := strconv.ParseUint(authBodySplit[2], 16, 32) // base: 16, size: 32-bit
		if err != nil {
			return ab, err
		}
		tokenRevocationID = uint32(tokenRevocationID64)
	}

	// Parse expiry
	tokenExpiry, err = time.Parse("2006-01-02T15:04:05", authBodySplit[3])
	if err != nil {
		return ab, err
	}

	// Parse identity

	ab.Identity = tokenIdentity
	ab.IpAddr = tokenIpAddr
	ab.RevocationID = tokenRevocationID
	ab.Expiry = tokenExpiry

	return ab, nil
}

func (ab *AuthBody) Base64() string {
	return hc.Base64Encoding(fmt.Sprintf("%0.8x%s%s%s%0.8x%s%s", ab.Identity, sepAuthFactor, ab.IpAddr, sepAuthFactor, ab.RevocationID, sepAuthFactor, ab.Expiry.UTC().Format("2006-01-02T15:04:05")))
}

func (ab *AuthBody) Initialized() bool {
	return ab.Identity != 0 && ab.IpAddr != nil && !ab.Expiry.IsZero() // All three factors must be set.
}

func (ab *AuthBody) HasRevocation() bool {
	return ab.RevocationID != 0
}
