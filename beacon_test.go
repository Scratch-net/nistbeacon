package nistbeacon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBeacon(t *testing.T){

	seed, err := GetBeaconData()
	assert.NoError(t, err)
	assert.True(t, len(seed)==64)
	assert.NotEqual(t, seed, make([]byte, 64))
}
