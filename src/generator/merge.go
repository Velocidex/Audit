package generator

// Merge rules from the other into this model
func (self *Rules) Merge(other *Rules) error {
	if other == nil {
		return nil
	}

	// Merge user settable
	self.ArtifactName = other.ArtifactName
	self.Precondition = other.Precondition
	self.Description = other.Description
	self.Export = other.Export

	// First build an index for fast lookup
	index := make(map[string]*Check)
	for _, o := range other.Checks {
		index[o.Id] = o
	}

	for _, c := range self.Checks {
		old_check, pres := index[c.Id]
		if !pres {
			continue
		}

		c.Merge(old_check)
	}

	return nil
}

func updateRule(r *Test) {
	if r.ColumnExpression == "CmdMatch(cmd=cmd, re=re)" && r.Context == "" {
		r.Context = "CmdContext(cmd=cmd, re=re)"
	}
}

func (self *Check) Merge(other *Check) error {
	if other == nil {
		return nil
	}

	self.Verified = other.Verified
	self.Remediate = other.Remediate

	// Do not mess with verified rules
	if other.Verified {
		self.Rules = other.Rules
		for _, r := range self.Rules {
			updateRule(r)
		}
		return nil
	}

	index := make(map[string]*Test)
	for _, t := range other.Rules {
		index[t.OriginalTest] = t
	}

	for _, t := range self.Rules {
		old_test, pres := index[t.OriginalTest]
		if pres {
			if old_test.Type != "" {
				t.Type = old_test.Type
			}

			if old_test.Name != "" {
				t.Name = old_test.Name
			}

			if old_test.ColumnExpression != "" {
				t.ColumnExpression = old_test.ColumnExpression
			}

			if old_test.WhereExpression != "" {
				t.WhereExpression = old_test.WhereExpression
			}

			if old_test.Env != nil {
				t.Env = old_test.Env
			}
		}
	}

	return nil
}
