package yarn

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/gmoyal-r7/fanal/analyzer"
	"github.com/gmoyal-r7/fanal/analyzer/language"
	"github.com/gmoyal-r7/fanal/types"
	"github.com/gmoyal-r7/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/yarn"
)

func init() {
	analyzer.RegisterAnalyzer(&yarnLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{"yarn.lock"}

type yarnLibraryAnalyzer struct{}

func (a yarnLibraryAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Yarn, target.FilePath, target.Content, yarn.Parse)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse yarn.lock: %w", err)
	}
	return res, nil
}

func (a yarnLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a yarnLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYarn
}

func (a yarnLibraryAnalyzer) Version() int {
	return version
}
