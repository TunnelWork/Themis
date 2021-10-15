package themis

import (
	"sync"
	"time"

	hc "github.com/TunnelWork/Harpocrates"
)

type revocationID uint

var (
	revocationMutex    = sync.RWMutex{}
	revocationRegistry = map[uint](map[revocationID]bool){}
)

func RevocationUserCheck(uid uint, rid revocationID) bool {
	revocationMutex.RLock()
	defer revocationMutex.RUnlock()
	if userReg, userOk := revocationRegistry[uid]; userOk {
		if userReg != nil { // Should be unnecessary
			if valid, revOk := userReg[rid]; revOk {
				return valid
			}
		}
	}
	return false
}

func NewRevocationID(uid uint) revocationID {
	revocationMutex.Lock()
	defer revocationMutex.Unlock()

	if userReg, userOk := revocationRegistry[uid]; userOk {
		if userReg == nil { // Shoudn't be needed?
			revocationRegistry[uid] = map[revocationID]bool{}
		}
	} else {
		revocationRegistry[uid] = map[revocationID]bool{}
	}

	// new revID
	rid := hc.GetRandomNumber(-1<<31, 1<<31-1)
	status, revFound := revocationRegistry[uid][rid]
	for revFound && status { // until not found or false
		time.Sleep(100 * time.Microsecond)
		rid = hc.GetRandomNumber(-1<<31, 1<<31-1)
		_, revFound = revocationRegistry[uid][rid]
	}
	revocationRegistry[uid][rid] = true
	return rid
}
