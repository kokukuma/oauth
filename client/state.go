package client

import "math/rand"

type stateHolder struct {
	states []string
}

func (s *stateHolder) add(state string) {
	s.states = append(s.states, state)
}

func (s *stateHolder) find(state string) bool {
	for _, i := range s.states {
		if i == state {
			return true
		}
	}
	return false
}

func (s *stateHolder) delete(state string) {
	ns := []string{}
	for _, i := range s.states {
		if i == state {
			continue
		}
		ns = append(ns, i)
	}
	s.states = ns
}

// generates a random string of fixed size
func createState(size int) string {
	alpha := "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, size)
	for i := 0; i < size; i++ {
		buf[i] = alpha[rand.Intn(len(alpha))]
	}
	return string(buf)
}

func newStateHolder() *stateHolder {
	return &stateHolder{
		states: []string{},
	}
}
