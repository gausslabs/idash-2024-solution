package keys

import (
	"fmt"
	"sync"

	"golang.org/x/exp/maps"

	"github.com/Pro7ech/lattigo/utils/concurrency"

	"github.com/Pro7ech/lattigo/he/hefloat"
	"github.com/Pro7ech/lattigo/rlwe"
)

type Manager struct {
	sync.Mutex
	Kgen               []*rlwe.KeyGenerator
	Sk                 *rlwe.SecretKey
	buff               chan *rlwe.GaloisKey
	GaloisKeys         map[uint64]*rlwe.GaloisKey
	RelinearizationKey *rlwe.RelinearizationKey
}

func NewManager(NumCPU int, params hefloat.Parameters, maxconcurrentkeys int, sk *rlwe.SecretKey) *Manager {
	Kgen := make([]*rlwe.KeyGenerator, NumCPU)
	for i := range Kgen {
		Kgen[i] = rlwe.NewKeyGenerator(params)
	}

	size := new(rlwe.GaloisKey).BufferSize(params)
	scratch := make([]uint64, size*maxconcurrentkeys)
	buff := make(chan *rlwe.GaloisKey, maxconcurrentkeys)
	for i := range maxconcurrentkeys {
		gk := new(rlwe.GaloisKey)
		gk.FromBuffer(params, scratch[i*size:(i+1)*size])
		buff <- gk
	}

	return &Manager{
		Kgen:               Kgen,
		Sk:                 sk,
		buff:               buff,
		GaloisKeys:         map[uint64]*rlwe.GaloisKey{},
		RelinearizationKey: Kgen[0].GenRelinearizationKeyNew(sk),
	}
}

func (km *Manager) LoadGaloisKeys(galEls []uint64) (err error) {
	previousGalEls := maps.Keys(km.GaloisKeys)
	currentGalEls := map[uint64]bool{}
	for _, galEl := range galEls {
		currentGalEls[galEl] = true
	}

	for _, galEl := range previousGalEls {
		if _, ok := currentGalEls[galEl]; !ok {
			km.buff <- km.GaloisKeys[galEl]
			delete(km.GaloisKeys, galEl)
		} else {
			delete(currentGalEls, galEl)
		}
	}

	galEls = maps.Keys(currentGalEls)
	newKeys := make([]*rlwe.GaloisKey, len(galEls))

	m := concurrency.NewRessourceManager[*rlwe.KeyGenerator](km.Kgen)
	for i, galEl := range galEls {
		m.Run(func(kgen *rlwe.KeyGenerator) (err error) {
			if len(km.buff) == 0 {
				return fmt.Errorf("maximum number of concurrent GaloisKeys exceeded")
			}
			gk := <-km.buff
			kgen.GenGaloisKey(galEl, km.Sk, gk)
			newKeys[i] = gk
			return
		})
	}

	if err = m.Wait(); err != nil {
		return
	}

	for _, gk := range newKeys {
		km.GaloisKeys[gk.GaloisElement] = gk
	}

	return
}

func (km *Manager) GetGaloisKey(galEl uint64) (gk *rlwe.GaloisKey, err error) {
	var ok bool
	if gk, ok = km.GaloisKeys[galEl]; ok {
		return gk, nil
	}
	return nil, fmt.Errorf("missing Galois Key %d", galEl)
}

func (km *Manager) GetGaloisKeysList() (galEls []uint64) {
	return maps.Keys(km.GaloisKeys)
}

func (km *Manager) GetRelinearizationKey() (rlk *rlwe.RelinearizationKey, err error) {
	return km.RelinearizationKey, nil
}

func (km *Manager) AsMemEvaluationKeySet() *rlwe.MemEvaluationKeySet {
	return &rlwe.MemEvaluationKeySet{
		RelinearizationKey: km.RelinearizationKey,
		GaloisKeys:         km.GaloisKeys,
	}
}
