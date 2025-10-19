package errors_test

import (
	"fmt"
	"testing"

	"github.com/masterkusok/crypto/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnnotate(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		var err error
		err = errors.Annotate(err, "annotaton: %w")

		require.NoError(t, err)
	})

	t.Run("actual error", func(t *testing.T) {
		err := fmt.Errorf("minus vibe")
		err = errors.Annotate(err, "annotaton with format %d %s: %w", 5, "aboba")
		require.Error(t, err)

		assert.Errorf(t, err, "annotaton with format 5 aboba: minus vibe")
	})
}
