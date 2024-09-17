package concurrency

import (
	"sync"
)

type ResourceManager[T any] struct {
	sync.WaitGroup
	Ressources chan T
	Errors     chan error
}

func NewRessourceManager[T any](ressources []T) *ResourceManager[T] {
	Ressources := make(chan T, len(ressources))
	for i := range ressources {
		Ressources <- ressources[i]
	}
	return &ResourceManager[T]{
		Ressources: Ressources,
		Errors:     make(chan error, len(ressources)),
	}
}

func (r *ResourceManager[T]) Run(f func(ressource T) (err error)) {
	r.Add(1)
	go func() {
		defer r.Done()
		if len(r.Errors) != 0 {
			return
		}
		ressource := <-r.Ressources
		if err := f(ressource); err != nil {
			if len(r.Errors) < cap(r.Errors) {
				r.Errors <- err
			}
		}
		r.Ressources <- ressource
	}()

	return
}

func (r *ResourceManager[T]) Wait() (err error) {
	if len(r.Errors) == 0 {
		r.WaitGroup.Wait()
	} else {
		return <-r.Errors
	}

	if len(r.Errors) != 0 {
		return <-r.Errors
	}

	return
}
