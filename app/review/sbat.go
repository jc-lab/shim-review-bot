package review

import (
	"strconv"
	"strings"
)

func parseSbat(sbat string) []*SbatItem {
	var list []*SbatItem

	lines := strings.Split(sbat, "\n")

	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		tokens := strings.Split(line, ",")
		version, _ := strconv.Atoi(tokens[1])
		list = append(list, &SbatItem{
			Vendor:  tokens[0],
			Version: version,
		})
	}

	return list
}
