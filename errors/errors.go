// Package errors represents some useful helpers for error-handling improvement.
package errors

import "fmt"

// ConstError is just a simple string error.
type ConstError string

// type check
var _ error = (*ConstError)(nil)

// Error implements [error] interface for ConstError.
func (e ConstError) Error() string {
	return string(e)
}

// Annotate wraps err with message unless err is nil.
func Annotate(err error, format string, args ...any) (annotated error) {
	if err == nil {
		return err
	}

	return fmt.Errorf(format, append(args, err)...)
}
