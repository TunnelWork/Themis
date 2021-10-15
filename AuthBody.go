package themis

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
	sepIdentityIpAddr string = "@"
	sepIpExpiry       string = "~"
)

var (
	ErrBadBase64Token error = errors.New("themis: bad base64 token")
	ErrIllformedBody  error = errors.New("themis: auth body is illformed")
	ErrBadIpAddr      error = errors.New("themis: cannot parse ip address")
)

type AuthBody struct {
	identity     uint
	ipAddr       net.IP
	expiry       time.Time
	revocationID revocationID
}

func NewAuthBody(authedIdentity uint, authedIP net.IP, validFor time.Duration) AuthBody {
	return AuthBody{
		identity:     authedIdentity,
		ipAddr:       authedIP,
		expiry:       time.Now().Add(validFor),
		revocationID: NewRevocationID(authedIdentity),
	}
}

func AuthBodyFromBase64(b64token string) (AuthBody, error) {
	var ab = AuthBody{}
	var tokenIdentity uint
	var tokenIpAddr net.IP
	var tokenExpiry time.Time

	decodeToken := hc.Base64Decoding(b64token)
	if decodeToken == "" {
		return ab, ErrBadBase64Token
	}

	// Parse expiry
	expirySplit := strings.Split(decodeToken, sepIpExpiry)
	if len(expirySplit) != 2 {
		return ab, ErrIllformedBody
	}
	tokenExpiry, err := time.Parse("2006-01-02T15:04:05", expirySplit[1])
	if err != nil {
		return ab, err
	}

	// Parse ipAddr
	ipSplit := strings.Split(expirySplit[0], sepIdentityIpAddr)
	if len(ipSplit) != 2 {
		return ab, ErrIllformedBody
	}
	tokenIpAddr = net.ParseIP(ipSplit[1])
	if tokenIpAddr == nil {
		return ab, ErrBadIpAddr
	}

	// Parse identity
	tokenIdentity64, err := strconv.ParseUint(ipSplit[0], 16, 32) // base: 16, size: 32-bit
	if err != nil {
		return ab, err
	}
	tokenIdentity = uint(tokenIdentity64)

	ab.identity = tokenIdentity
	ab.ipAddr = tokenIpAddr
	ab.expiry = tokenExpiry

	return ab, nil
}

func (ab *AuthBody) Base64() string {
	return hc.Base64Encoding(fmt.Sprintf("%0.8x%s%s%s%s", ab.identity, sepIdentityIpAddr, ab.ipAddr, sepIpExpiry, ab.expiry.UTC().Format("2006-01-02T15:04:05")))
}

func (ab *AuthBody) Initialized() bool {
	return ab.identity != 0 && ab.ipAddr != nil && !ab.expiry.IsZero() // All three factors must be set.
}
