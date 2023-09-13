package parse_comment

import (
	_ "embed"
	"github.com/stretchr/testify/assert"
	"testing"
)

//go:embed testdata/sample-1.md
var sample1 []byte

//go:embed testdata/sample-2.md
var sample2 []byte

func TestSample1(t *testing.T) {
	result, err := CommentParse(string(sample1))
	if err != nil {
		t.Error(err)
		return
	}

	assert.Equal(t, "https://github.com/jc-lab/shim-review-bot/tree/master/sample-repo", result.Source)
}

func TestSample2(t *testing.T) {
	result, err := CommentParse(string(sample2))
	if err != nil {
		t.Error(err)
		return
	}

	assert.Equal(t, "https://github.com/jc-lab/shim-review-bot/tree/master/sample-repo", result.Source)
	assert.Equal(t, "build.sh", result.BuildScript)
	assert.Equal(t, "output.tar", result.OutputFile)
	assert.Equal(t, "vendor_cert.der", result.VendorCert)
	assert.Equal(t, "sbat.csv", result.Sbat)
}
