## VQL Checks

This project maintains a set of `Checks` that will be converted to a
VQL artifact.

### What are checks?

A check is a simple boolean Yes/No question - for example, does this
system enable account lockout? The check will specify a `test` with an
`expected outcome` and a `measured outcome`. If these differ we say
the test failed.

One common use case for checks is compliance and hardening guides. In
this context, a check may indicate a potential for remediation.

A test will also contain an explanation as to what the test means and
how it should be interpreted.

## Running Checks on a live System

The output of this project is a VQL artifact that should be collected
on the live system. The artifact will generate a set of results
