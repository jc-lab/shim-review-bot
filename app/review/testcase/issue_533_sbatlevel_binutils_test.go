package testcase

import (
	_ "embed"
	"github.com/stretchr/testify/assert"
	"testing"
)

//go:embed testdata/issue-533-sbatlevel-good.bin
var issue533sbatlevelGoodBin []byte

//go:embed testdata/issue-533-sbatlevel-bad.bin
var issue533sbatlevelBadBin []byte

func TestIssue533SbatLevelBinUtils_Good(t *testing.T) {
	assert.True(t, validateIssue533SbatLevelBinUtils(issue533sbatlevelGoodBin))
}

func TestIssue533SbatLevelBinUtils_Bad(t *testing.T) {
	assert.False(t, validateIssue533SbatLevelBinUtils(issue533sbatlevelBadBin))
}
