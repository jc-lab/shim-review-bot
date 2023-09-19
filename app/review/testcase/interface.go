package testcase

import "debug/pe"

type TestContext struct {
	Pe *pe.File
}

type TestResult struct {
	Name    string
	Result  bool
	Message string
}

func DoTests(testContext *TestContext) []*TestResult {
	var results []*TestResult
	results = append(results, CheckIssue533SbatLevelBinUtils(testContext))
	return results
}
