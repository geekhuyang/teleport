/*
Copyright 2017-2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package parse

import (
	"go/ast"
	"go/parser"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/gravitational/trace"
)

// Expression is an expression template
// that can interpolate to some variables
type Expression struct {
	// name
	namespace string
	// variable is a variable name, e.g. trait name
	variable string
	// prefix is a prefix of the string
	prefix string
	// suffix is a suffix
	suffix string
}

// Namespace returns a variable namespace, e.g. external or internal
func (p *Expression) Namespace() string {
	return p.namespace
}

// Name returns variable name
func (p *Expression) Name() string {
	return p.variable
}

// Interpolate interpolates the variable adding prefix and suffix if present
func (p *Expression) Interpolate(traits map[string][]string) ([]string, bool) {
	values, ok := traits[p.variable]
	if !ok {
		return nil, false
	}
	out := make([]string, len(values))
	for i := range values {
		out[i] = p.prefix + values[i] + p.suffix
	}
	return out, true
}

var reVariable = regexp.MustCompile(
	// prefix is anyting that is not { or }
	`^(?P<prefix>[^}{]*)` +
		// variable is antything in brackets {{}} that is not { or }
		`{{(?P<expression>\s*[^}{]*\s*)}}` +
		// prefix is anyting that is not { or }
		`(?P<suffix>[^}{]*)$`,
)

// RoleVariable checks if the passed in string matches the variable pattern
// {{external.foo}} or {{internal.bar}}. If it does, it returns the variable
// prefix and the variable name. In the previous example this would be
// "external" or "internal" for the variable prefix and "foo" or "bar" for the
// variable name. If no variable pattern is found, trace.NotFound is returned.
func RoleVariable(variable string) (*Expression, error) {
	match := reVariable.FindStringSubmatch(variable)
	if len(match) == 0 {
		if strings.Index(variable, "{{") != -1 || strings.Index(variable, "}}") != -1 {
			return nil, trace.BadParameter(
				"%q is using template brackets '{{' or '}}', however expression does not parse, make sure the format is {{variable}}",
				variable)
		}
		return nil, trace.NotFound("no variable found in %q", variable)
	}

	prefix, variable, suffix := match[1], match[2], match[3]

	// parse and get the ast of the expression
	expr, err := parser.ParseExpr(variable)
	if err != nil {
		return nil, trace.NotFound("no variable found: %v", variable)
	}

	// walk the ast tree and gather the variable parts
	variableParts, err := walk(expr)
	if err != nil {
		return nil, trace.NotFound("no variable found: %v", variable)
	}

	// the variable must have two parts the prefix and the variable name itself
	if len(variableParts) != 2 {
		return nil, trace.NotFound("no variable found: %v", variable)
	}

	return &Expression{
		prefix:    strings.TrimLeftFunc(prefix, unicode.IsSpace),
		namespace: variableParts[0],
		variable:  variableParts[1],
		suffix:    strings.TrimRightFunc(suffix, unicode.IsSpace),
	}, nil
}

// walk will walk the ast tree and gather all the variable parts into a slice and return it.
func walk(node ast.Node) ([]string, error) {
	var l []string

	switch n := node.(type) {
	case *ast.IndexExpr:
		ret, err := walk(n.X)
		if err != nil {
			return nil, err
		}
		l = append(l, ret...)

		ret, err = walk(n.Index)
		if err != nil {
			return nil, err
		}
		l = append(l, ret...)
	case *ast.SelectorExpr:
		ret, err := walk(n.X)
		if err != nil {
			return nil, err
		}
		l = append(l, ret...)

		ret, err = walk(n.Sel)
		if err != nil {
			return nil, err
		}
		l = append(l, ret...)
	case *ast.Ident:
		return []string{n.Name}, nil
	case *ast.BasicLit:
		value, err := strconv.Unquote(n.Value)
		if err != nil {
			return nil, err
		}
		return []string{value}, nil
	default:
		return nil, trace.BadParameter("unknown node type: %T", n)
	}

	return l, nil
}
