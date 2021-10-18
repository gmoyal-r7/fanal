package cargo

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/gmoyal-r7/fanal/analyzer"
	"github.com/gmoyal-r7/fanal/analyzer/language"
	"github.com/gmoyal-r7/fanal/types"
	"github.com/gmoyal-r7/fanal/utils"
	"github.com/aquasecurity/go-dep-parser/pkg/rust/cargo"
)

func init() {
	analyzer.RegisterAnalyzer(&cargoLibraryAnalyzer{})
}

const version = 1

var requiredFiles = []string{"Cargo.lock"}

type cargoLibraryAnalyzer struct{}

func (a cargoLibraryAnalyzer) Analyze(_ context.Context, target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Cargo, target.FilePath, target.Content, cargo.Parse)
	if err != nil {
		return nil, xerrors.Errorf("error with Cargo.lock: %w", err)
	}
	return res, nil
}

func (a cargoLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return utils.StringInSlice(fileName, requiredFiles)
}

func (a cargoLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCargo
}

func (a cargoLibraryAnalyzer) Version() int {
	return version
}
