package generator

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/velociraptor/json"
)

func indent(text string, indent string) string {
	return indent + strings.ReplaceAll(text, "\n", "\n"+indent)
}

func (self *Rules) BuildArtifact(name string) string {
	return fmt.Sprintf(`
name: %v
parameters:
- name: OverruleChecks
  default: |
    Id,Title,Reason
    0,RuleTitle,Reason For Overruling

- name: Remediate
  type: bool
  description: If enabled we remediate the configuration if possible.

sources:
- name: FailedChecks
  query: |
%v
    SELECT * FROM Failours

- name: FailedTests
  query: |
    -- For failed checks show all tests
    SELECT Id, TestId, CheckDetails, Value, pass
    FROM foreach(row={
      SELECT Id AS FailedId FROM Failours
    },
    query={
      SELECT *,
         get(item=Env,
             member=format(format="%%v.%%v", args=[Id, TestId])) AS CheckDetails
      FROM AllTests
      WHERE Id = FailedId
    })

- name: AllTests
  query: |
    SELECT * FROM AllTests

- name: Remediation
  query: |
%v

- name: Stats
  query: |
    LET TotalFailed <= SELECT count() AS Total FROM Failours GROUP BY 1
    LET TotalChecks <= %d

    SELECT TotalFailed[0].Total AS TotalFailed, TotalChecks FROM scope()

`, name, indent(self.BuildVQL(), "    "),
		indent(self.BuildRemediations(), "    "), len(self.Checks))
}

func (self *Rules) encodeJsonBlob(blob interface{}) string {
	serialized, _ := json.Marshal(blob)

	// Compress the string
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	gz.Write(serialized)
	gz.Close()
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func (self *Rules) BuildRemediations() string {
	parts := []string{}
	for idx, t := range self.Checks {
		if t.Remediate != "" {
			parts = append(parts,
				fmt.Sprintf(`r%d={ SELECT Id, Title,
       %v AS _Result
       FROM Check%vStatus WHERE NOT OK }`,
					idx, t.Remediate, t.Id))
		}
	}

	result := fmt.Sprintf(`
SELECT * FROM if(condition=Remediate, then={
  SELECT * FROM chain(
%v
)})
`, indent(strings.Join(parts, ",\n"), "  "))

	return result
}

// Produce a VQL query from the rules
func (self *Rules) BuildVQL() string {
	parts := []string{}
	env := ordereddict.NewDict()

	for _, c := range self.Checks {
		if c.Verified {
			test_env := ordereddict.NewDict()
			env.Set(c.Id, test_env)
			parts = append(parts, c.BuildVQL(test_env))
		}
	}

	preamble := fmt.Sprintf(`
LET JSONEnv = "%v"
LET Env <= parse_json(data=gunzip(string=base64decode(string=JSONEnv)))

LET C(E) = if(condition=E, then=1, else=0)

LET OverruleChecks <= SELECT * FROM if(
    condition=format(format="%%T", args=OverruleChecks) =~ "string",
    then={ SELECT * FROM parse_csv(filename=OverruleChecks, accessor='data')})

LET O <= OverruleChecks.Id

LET _Cmd(cmd) = SELECT Stdout
  FROM execve(argv=commandline_split(command=cmd), length=1000000)

LET CmdOut(cmd, re) = parse_string_with_regex(regex=re,
    string=cache(func=_Cmd(cmd=cmd)[0].Stdout, key=cmd))

LET CmdMatch(cmd, re) = cache(func=_Cmd(cmd=cmd)[0].Stdout, key=cmd) =~ re

LET _Reg(Path) = SELECT Data FROM stat(filename=Path, accessor="registry")

LET Reg(k) = _Reg(Path=k)[0].Data

%v

`, self.encodeJsonBlob(env), self.Export)

	chained_status := []string{}
	chained_all := []string{}
	for i, c := range self.Checks {
		if !c.Verified {
			continue
		}
		chained_status = append(chained_status,
			fmt.Sprintf("a%d=Check%vStatus", i, c.Id))
		chained_all = append(chained_all,
			fmt.Sprintf("a%d=Check%v", i, c.Id))
	}

	postscript := fmt.Sprintf(`
LET Failours <= SELECT * FROM chain(%v)
WHERE NOT OK

LET AllTests <= SELECT * FROM chain(%v)
`, strings.Join(chained_status, ",\n "),
		strings.Join(chained_all, ",\n "))

	return preamble + strings.Join(parts, "\n") + postscript
}

func (self *Check) BuildVQL(env *ordereddict.Dict) string {
	parts := []string{}
	for idx, t := range self.Rules {
		// The index of this test inside the overall check
		test_idx := fmt.Sprintf("%v", idx)
		test_env := ordereddict.NewDict()
		if t.Env != nil {
			test_env.MergeFrom(t.Env)
		}

		test_env.Set("expected", t.WhereExpression).
			Set("Title", self.Title).
			Set("Value", t.ColumnExpression).
			Set("Id", self.Id).
			Set("Cond", self.Condition)

		env.Set(test_idx, test_env)

		parts = append(parts, fmt.Sprintf(`
t%d={
  SELECT %v AS Id, %v AS TestId, Title,
     C(E=%v) AS pass, %v, expected
  FROM foreach(row={
    SELECT *, %v AS %v
    FROM foreach(row=%s)
  })
}`,
			idx, self.Id, idx, t.WhereExpression, t.Name,
			t.ColumnExpression, t.Name,
			fmt.Sprintf("Env.`%s`.`%s`", self.Id, test_idx),
		))
	}

	// Depending on the condition we have different criteria for
	// "passing" the check.
	var condition string
	switch self.Condition {
	case "all":
		// All tests must match
		condition = fmt.Sprintf("sum(item=pass) = %d", len(self.Rules))
	case "any":
		// Any test must pass
		condition = "sum(item=pass) > 0"
	case "none":
		// No condition should match
		condition = "sum(item=pass) = 0"
	default:
		condition = "'Invalid Condition'"
	}

	return fmt.Sprintf(`
LET Check%v <= SELECT * FROM chain(%v)

LET Check%vStatus <= SELECT Id, Title, %v OR Id IN O AS OK
FROM Check%v
GROUP BY 1
`, self.Id, strings.Join(parts, ","), self.Id, condition, self.Id)
}
