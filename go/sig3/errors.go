package sig3

import (
	"fmt"
)

type ParseError struct {
	m string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("parse error: %s", e.m)
}

func newParseError(f string, a ...interface{}) error {
	return ParseError{m: fmt.Sprintf(f, a...)}
}

type Sig3Error struct {
	m string
}

func (e Sig3Error) Error() string {
	return fmt.Sprintf("sig3 error: %s", e.m)
}

func newSig3Error(f string, a ...interface{}) error {
	return Sig3Error{m: fmt.Sprintf(f, a...)}
}

var _ error = ParseError{}
var _ error = Sig3Error{}
