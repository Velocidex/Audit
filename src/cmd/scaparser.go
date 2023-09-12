package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Velocidex/Audit/src/generator"
	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/yaml/v2"
)

// Get the sca file from https://github.com/wazuh/wazuh/blob/master/ruleset/sca/windows/cis_win2019.yml
var (
	sca_parser = app.Command(
		"sca", "Parse SCA rules into intermediate model")
	app_file_arg = sca_parser.Arg(
		"file", "The sca file to parse",
	).Required().String()

	output_file = sca_parser.Arg(
		"output", "Where to save the model",
	).Required().String()
)

// Used to parse the SCA files
type Check struct {
	Id        int
	Title     string
	Condition string
	Rules     []string
}

type RuleSet struct {
	Checks []Check
}

var (
	reg_check_regex      = regexp.MustCompile("^r:(.+) -> (.+) -> (.+)")
	numberic_check_regex = regexp.MustCompile("^n:")
	number_regex         = regexp.MustCompile("^[0-9]+$")
	command_regex        = regexp.MustCompile(`^c:(.+) +-> +n:(.+) +compare(.+)`)
)

func ParseRule(id int, title string, rule string) string {
	matches := reg_check_regex.FindStringSubmatch(rule)
	if len(matches) != 0 {
		var comparison string
		expected := matches[3]
		value_name := matches[2]

		// A regex match
		if strings.HasPrefix(expected, "r:") {
			comparison = fmt.Sprintf(`get(field='''%v''') =~ '''%v''' AS OK`,
				value_name, expected[2:])

			// Numeric match
		} else if number_regex.MatchString(expected) {
			comparison = fmt.Sprintf(`int(int=get(field='''%v''')) = %v AS OK`, value_name, expected)

		} else if numberic_check_regex.MatchString(expected) {
			comparison = fmt.Sprintf(`-- int(int=get(field='''%v''')) = %v AS OK
    "Unknown" AS OK`, value_name, expected)

		} else {
			// Unknown rule type
			comparison = `"Unknown" AS OK`
		}

		// A registry search rule
		return fmt.Sprintf(`
      SELECT %v AS ID,
        '''%v ''' AS Title,
        get(field='''%v''') AS ActualValue,
        '''%v''' AS ExpectedValue,
        %v
      FROM read_reg_key(globs='''%v''')
`, id, title, matches[2], expected, comparison, matches[1])
	}
	return ""
}

func ConvertToVQL(ruleset *RuleSet) {
	fmt.Println("    SELECT * FROM chain(")
	parts := []string{}
	for idx, check := range ruleset.Checks {
		for idx2, rule := range check.Rules {
			query := ParseRule(check.Id, check.Title, rule)
			if query != "" {
				parts = append(parts,
					fmt.Sprintf("    id%v_%v={\n%v\n    }", idx, idx2, query))
			}
		}
	}

	fmt.Println(strings.Join(parts, ", ") + ")")
}

var (
	command_with_numeric_check_regex = regexp.MustCompile(`^c:(.+) +-> +n:(.+) +compare(.+)`)

	command_with_regex   = regexp.MustCompile(`^c:(.+) +-> +r:(.+)`)
	command_with_2_regex = regexp.MustCompile(`^c:(.+) +-> +r:(.+?) +&& +(r:.+)`)

	reg_value_numeric_regex     = regexp.MustCompile(`^r:(.+) +-> (.+) +-> n:.+compare +(.+)$`)
	reg_value_match_regex       = regexp.MustCompile(`^r:(.+) +-> (.+) +-> +(.+)$`)
	reg_value_regex_match_regex = regexp.MustCompile(`^r:(.+) +-> +(.+) +-> +r:+(.+)$`)
	reg_value_exists_regex      = regexp.MustCompile(`^r:(.+) +-> (.+)$`)
	reg_key_exists_regex        = regexp.MustCompile(`^r:(.+)$`)
	not_regex                   = regexp.MustCompile(`^not +(.+)$`)

	file_exists_regex = regexp.MustCompile(`^f:(.+)`)
	file_with_regex   = regexp.MustCompile(`^f:(.+) +-> +r:(.+)`)
)

func parseSCARule(rule *generator.Test) []*generator.Test {
	matches := not_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		original := rule.OriginalTest
		rule.WhereExpression = ""
		rule.OriginalTest = matches[1]
		extra := parseSCARule(rule)

		rule.WhereExpression = "NOT " + rule.WhereExpression
		rule.OriginalTest = original
		return extra
	}

	// Check for a command: Example
	// c:net.exe accounts -> n:Length of password history maintained:\\s+(\\d+) compare <= 24
	matches = command_with_numeric_check_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.
			Set("cmd", matches[1]).
			Set("re", matches[2])
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf(
			"int(int=CmdOut(cmd=cmd, re=re).g1 || 0)")
		rule.WhereExpression = fmt.Sprintf("Value %v", matches[3])
		return nil
	}

	matches = command_with_2_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.
			Set("cmd", matches[1]).
			Set("re", matches[2])
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf("CmdMatch(cmd=cmd, re=re)")
		rule.WhereExpression = "Value"

		extras := []*generator.Test{}

		// Sometimes the next steps have an && as well
		extra_parts := strings.Split(matches[3], " && ")
		for _, extra_part := range extra_parts {

			// Make a copy for the next rule.
			extra := &generator.Test{
				Name:             rule.Name,
				ColumnExpression: rule.ColumnExpression,
				WhereExpression:  rule.WhereExpression,
				Env: ordereddict.NewDict().
					Set("cmd", matches[1]).
					Set("re", strings.TrimPrefix(extra_part, "r:")),
			}
			extras = append(extras, extra)
		}
		return extras
	}

	matches = command_with_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.
			Set("cmd", matches[1]).
			Set("re", matches[2])
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf("CmdMatch(cmd=cmd, re=re)")
		rule.WhereExpression = "Value"
		return nil
	}

	matches = reg_value_numeric_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.Set("k", matches[1]).Set("v", matches[2])
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf("int(int=Reg(k=k + '/' + v).value)")
		rule.WhereExpression = fmt.Sprintf("Value %v", matches[3])
		return nil
	}

	matches = reg_value_regex_match_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.Set("k", matches[1]).Set("v", matches[2]).Set("regex", matches[3])
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf("Reg(k=k + '/' + v).value")
		rule.WhereExpression = "Value =~ regex"
		return nil
	}

	matches = reg_value_match_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.Set("k", matches[1]).Set("v", matches[2])
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf("Reg(k=k + '/' + v).value")
		rule.WhereExpression = fmt.Sprintf("Value = %v", matches[3])
		return nil
	}

	matches = reg_value_exists_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.Set("k", matches[1]).Set("v", matches[2])
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf("Reg(k=k + '/' + v)")
		rule.WhereExpression = fmt.Sprintf("Value")
		return nil
	}

	matches = reg_key_exists_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.Set("k", matches[1])
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf("Reg(k=k)")
		rule.WhereExpression = fmt.Sprintf("Value")
		return nil
	}

	matches = file_with_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.Set("f", matches[1]).Set("re", matches[2])
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf("FMatch(f=f, re=re)")
		rule.WhereExpression = fmt.Sprintf("Value")
		return nil
	}

	matches = file_exists_regex.FindStringSubmatch(rule.OriginalTest)
	if len(matches) > 0 {
		if rule.Env == nil {
			rule.Env = ordereddict.NewDict()
		}
		rule.Env.Set("f", matches[1]).Set("re", "..")
		rule.Name = "Value"
		rule.ColumnExpression = fmt.Sprintf("FMatch(f=f, re=re)")
		rule.WhereExpression = fmt.Sprintf("Value")
		return nil
	}

	return nil
}

// Do our best to convert from SCA rule format to VQL.
func compileCheck(check *generator.Check) {
	// Ignore checks that were manually verified.
	if !check.Disabled {
		return
	}

	extra := []*generator.Test{}
	for _, c := range check.Rules {
		extra = append(extra, parseSCARule(c)...)
	}

	check.Rules = append(check.Rules, extra...)
}

func buildModel(
	filename string, rule_file *RuleSet) *generator.Rules {
	res := &generator.Rules{
		Source: filename,
		Type:   "SCA",
	}

	for _, c := range rule_file.Checks {
		check := &generator.Check{
			Id:        fmt.Sprintf("%v", c.Id),
			Title:     c.Title,
			Condition: c.Condition,

			// New checks are set to disabled until we can verify
			// them.
			Disabled: true,
		}

		for _, r := range c.Rules {
			check.Rules = append(check.Rules, &generator.Test{
				OriginalTest: r,
			})
		}

		res.Checks = append(res.Checks, check)
	}

	return res
}

func doParse() (*generator.Rules, error) {
	rule_file := &RuleSet{}
	fd, err := os.Open(*app_file_arg)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, rule_file)
	if err != nil {
		return nil, err
	}

	model := buildModel(filepath.Base(*app_file_arg), rule_file)
	return model, nil
}

func doParseSCA() error {
	old_model, err := generator.LoadModel(*output_file)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	model, err := doParse()
	if err != nil {
		return err
	}

	err = model.Merge(old_model)
	if err != nil {
		return err
	}

	// Compile the check
	for _, c := range model.Checks {
		compileCheck(c)
	}

	return model.Save(*output_file)
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case sca_parser.FullCommand():
			FatalIfError(sca_parser, doParseSCA)
		}
		return false
	})
}
