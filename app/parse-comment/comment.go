package parse_comment

import (
	"bufio"
	"fmt"
	"github.com/jc-lab/shim-review-bot/app/config"
	"gopkg.in/yaml.v3"
	"regexp"
	"strings"
)

type ParsedComment struct {
	config.Config
}

type readState int

const (
	stateIdle readState = iota
	stateYaml readState = iota
	stateEnd  readState = iota
)

var (
	beginPattern = regexp.MustCompile("/review-bot\\s+([^ \r\n\t]+)")
)

func CommentParse(input string) (*ParsedComment, error) {
	result := &ParsedComment{}

	beginAt := strings.Index(input, "/review-bot ")
	if beginAt < 0 {
		return nil, fmt.Errorf("cannot found \"review-bot \" message")
	}
	input = input[beginAt:]

	matches := beginPattern.FindStringSubmatch(input)
	result.Source = matches[1]

	scanner := bufio.NewScanner(strings.NewReader(input))
	currentState := stateIdle
	argsYaml := ""
	for scanner.Scan() {
		line := scanner.Text()
		switch currentState {
		case stateIdle:
			if strings.HasPrefix(line, "```") {
				currentState = stateYaml
			}
		case stateYaml:
			if strings.HasPrefix(line, "```") {
				currentState = stateEnd
			} else {
				argsYaml += line + "\n"
			}
		default:
		}
	}

	if err := yaml.Unmarshal([]byte(argsYaml), &result.Config); err != nil {
		return nil, err
	}

	return result, nil
}
