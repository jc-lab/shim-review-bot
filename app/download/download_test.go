package download

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGithubTreeUrl1(t *testing.T) {
	parsed := ParseSourceUrl("https://github.com/jc-lab/shim-review-bot/tree/master")
	assert.NotNil(t, parsed)

	assert.Equal(t, "https://github.com/jc-lab/shim-review-bot.git", parsed.RepositoryUrl)
	assert.Equal(t, "master", parsed.Tag)
	assert.Equal(t, "", parsed.Directory)
}

func TestGithubTreeUrl2(t *testing.T) {
	parsed := ParseSourceUrl("https://github.com/jc-lab/shim-review-bot/tree/master/")
	assert.NotNil(t, parsed)

	assert.Equal(t, "https://github.com/jc-lab/shim-review-bot.git", parsed.RepositoryUrl)
	assert.Equal(t, "master", parsed.Tag)
	assert.Equal(t, "", parsed.Directory)
}

func TestGithubTreeUrl3(t *testing.T) {
	parsed := ParseSourceUrl("https://github.com/jc-lab/shim-review-bot/tree/master/sample-repo")
	assert.NotNil(t, parsed)

	assert.Equal(t, "https://github.com/jc-lab/shim-review-bot.git", parsed.RepositoryUrl)
	assert.Equal(t, "master", parsed.Tag)
	assert.Equal(t, "sample-repo", parsed.Directory)
}

func TestBitbucketSrcUrl1(t *testing.T) {
	parsed := ParseSourceUrl("https://bitbucket.org/hello/world/src/tag01/")
	assert.NotNil(t, parsed)

	assert.Equal(t, "https://bitbucket.org/hello/world.git", parsed.RepositoryUrl)
	assert.Equal(t, "tag01", parsed.Tag)
	assert.Equal(t, "", parsed.Directory)
}
