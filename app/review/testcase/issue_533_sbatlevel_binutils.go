package testcase

import (
	"bytes"
	"encoding/hex"
	"log"
)

// Issue: https://github.com/rhboot/shim/issues/533

func CheckIssue533SbatLevelBinUtils(testContext *TestContext) *TestResult {
	result := &TestResult{
		Name: "buggy gcc/binutils #533",
	}

	section := testContext.Pe.Section(".sbatlevel")
	data, err := section.Data()
	if err != nil {
		log.Println("read sbatlevel section failed: ", err)
		return result
	}
	data = data[:section.VirtualSize]

	if validateIssue533SbatLevelBinUtils(data) {
		result.Name += ": Not affected"
		result.Result = true
	} else {
		result.Name += ": Affected!!!"
		result.Message = "```\n" + hex.Dump(data) + "\n```"
	}

	return result
}

func validateIssue533SbatLevelBinUtils(data []byte) bool {
	// remove header
	data = data[12 : len(data)-1]
	return !bytes.Contains(data, []byte{',', 0})
}
