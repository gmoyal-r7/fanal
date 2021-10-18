package remote

import (
	"context"
	"io/ioutil"
	"net/url"
	"os"

	git "github.com/go-git/go-git/v5"
	"golang.org/x/xerrors"

	"github.com/gmoyal-r7/fanal/analyzer/config"
	"github.com/gmoyal-r7/fanal/artifact"
	"github.com/gmoyal-r7/fanal/artifact/local"
	"github.com/gmoyal-r7/fanal/cache"
	"github.com/gmoyal-r7/fanal/types"
)

type Artifact struct {
	url   string
	local artifact.Artifact
}

func NewArtifact(rawurl string, c cache.ArtifactCache, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (
	artifact.Artifact, func(), error) {
	cleanup := func() {}

	u, err := newURL(rawurl)
	if err != nil {
		return nil, cleanup, err
	}

	tmpDir, err := ioutil.TempDir("", "fanal-remote")
	if err != nil {
		return nil, cleanup, err
	}

	_, err = git.PlainClone(tmpDir, false, &git.CloneOptions{
		URL:      u.String(),
		Progress: os.Stdout,
		Depth:    1,
	})
	if err != nil {
		return nil, cleanup, xerrors.Errorf("git error: %w", err)
	}

	cleanup = func() {
		_ = os.RemoveAll(tmpDir)
	}

	art, err := local.NewArtifact(tmpDir, c, artifactOpt, scannerOpt)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("fs artifact: %w", err)
	}

	return Artifact{
		url:   rawurl,
		local: art,
	}, cleanup, nil
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	ref, err := a.local.Inspect(ctx)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("remote repository error: %w", err)
	}

	ref.Name = a.url
	ref.Type = types.ArtifactRemoteRepository

	return ref, nil
}

func newURL(rawurl string) (*url.URL, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, xerrors.Errorf("url parse error: %w", err)
	}
	// "https://" can be omitted
	// e.g. github.com/aquasecurity/fanal
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	return u, nil
}
