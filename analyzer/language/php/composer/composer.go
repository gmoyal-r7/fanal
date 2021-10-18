package composer

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/gmoyal-r7/fanal/analyzer"
	"github.com/gmoyal-r7/fanal/analyzer/language"
	"github.com/gmoyal-r7/fanal/types"
	"github.com/gmoyal-r7/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/php/composer"
)

func init() {
	analyzer.RegisterAnalyzer(&composerLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{"composer.lock"}

type composerLibraryAnalyzer struct{}

func (a composerLibraryAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Composer, target.FilePath, target.Content, composer.Parse)
	if err != nil {
		return nil, xerrors.Errorf("error with composer.lock: %w", err)
	}
	return res, nil
}

func (a composerLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a composerLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposer
}

func (a composerLibraryAnalyzer) Version() int {
	return version
}
