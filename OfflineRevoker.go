package themis

// OfflineRevoker uses a map for registration.

import (
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"
)

var (
	ErrOfflineRevokerNotEnoughParams error = errors.New("themis: not enough parameters for offline revoker")
	ErrBadRevocationID               error = errors.New("themis: invalid revocation id or token has been revoked")
)

type OfflineRevocationRecord struct {
	Creator      net.IP    // Registered for
	CreationTime time.Time // Registered at
	LastActive   time.Time // Last time it calls Validate()
}

type RevocationRecordMap map[uint32]OfflineRevocationRecord

type ConcurrentRRMap struct {
	lock  *sync.Mutex
	rrMap RevocationRecordMap
}

// A *OfflineRevoker shall implement Revoker interface
type OfflineRevoker struct {
	sgl      *sync.Mutex
	registry map[uint32]ConcurrentRRMap // map[userID](map[revocationID])
}

func NewOfflineRevoker() *OfflineRevoker {
	return &OfflineRevoker{
		sgl:      &sync.Mutex{},
		registry: map[uint32]ConcurrentRRMap{},
	}
}

func (orev *OfflineRevoker) Register(uid uint32, params ...interface{}) (uint32, error) { // skipcq: GSC-G404
	orev.sgl.Lock()
	defer orev.sgl.Unlock()
	var rid uint32
	var createdAt time.Time = time.Now()
	orr := OfflineRevocationRecord{
		Creator:      nil,
		CreationTime: createdAt,
		LastActive:   createdAt,
	}

	// parse params.
	for _, p := range params {
		if ip, ok := p.(net.IP); ok {
			orr.Creator = ip
			break
		}
	}

	if orr.Creator == nil {
		return 0, ErrOfflineRevokerNotEnoughParams
	}

	rid = rand.Uint32()

	// Check if user's map exists
	if umap, exist := orev.registry[uid]; exist {
		umap.lock.Lock()
		defer umap.lock.Unlock()
		umap.rrMap[rid] = orr
	} else {
		// Otherwise need to create a user map
		orev.registry[uid] = ConcurrentRRMap{
			lock:  &sync.Mutex{},
			rrMap: RevocationRecordMap{},
		}
		orev.registry[uid].lock.Lock()
		defer orev.registry[uid].lock.Unlock()
		orev.registry[uid].rrMap[rid] = orr
	}

	return rid, nil
}

func (orev *OfflineRevoker) Validate(uid uint32, id uint32) error {
	orev.sgl.Lock()
	defer orev.sgl.Unlock()
	if umap, exist := orev.registry[uid]; exist {
		// usermap exists
		umap.lock.Lock()
		defer umap.lock.Unlock()
		if rec, ok := umap.rrMap[id]; ok {
			// revocation id exists in usermap
			rec.LastActive = time.Now()
			return nil
		}
	}
	return ErrBadRevocationID
}

func (orev *OfflineRevoker) Revoke(uid uint32, id uint32) error {
	orev.sgl.Lock()
	defer orev.sgl.Unlock()
	if umap, exist := orev.registry[uid]; exist {
		// usermap exists
		umap.lock.Lock()
		defer umap.lock.Unlock()
		if _, ok := umap.rrMap[id]; ok {
			// revocation id exists in usermap
			delete(umap.rrMap, id)
			return nil
		}
	}
	return ErrBadRevocationID
}
