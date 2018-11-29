// +build ignore

package main

import (
	"bytes"
	"encoding/asn1"
	"flag"
	"fmt"
	"go/format"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type oid struct {
	asn1.ObjectIdentifier
	Name string
}

type oids []oid

func (s oids) Len() int           { return len(s) }
func (s oids) Less(i, j int) bool { return s[i].String() < s[j].String() }
func (s oids) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

var spaces = regexp.MustCompile(`\s+`)

func main() {
	output := flag.String("o", "oids.go", "output file")
	flag.Parse()

	b, err := ioutil.ReadFile("oids.txt")
	if err != nil {
		panic(err)
	}

	w := new(bytes.Buffer)
	if *output == "" {
		fmt.Fprintf(w, "//go:generate go run oids_gen.go -o -\n\n")
	} else {
		fmt.Fprintf(w, "//go:generate go run oids_gen.go -o %s\n\n", *output)
	}
	w.WriteString("package main\n\n")
	w.WriteString("import (\n\t\"encoding/asn1\"\n\t\"fmt\"\n)\n")

	var all, bases oids
	w.WriteString("// Object identifiers\nvar (\n")
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimRight(line, " \r\n\t"); line == "" || line[0] == '#' {
			continue
		}

		var (
			isBase = line[0] == '!'
			part   = spaces.Split(line[1:], 2)
			curr   = parseObjectIdentifier(part[0])
			name   = part[1]
		)
		if isBase {
			bases = append(bases, oid{Name: name})
		}
		all = append(all, oid{ObjectIdentifier: curr, Name: name})
		fmt.Fprintf(w, "\t%s = asn1.ObjectIdentifier{%s} // %s\n", oidName(name), oidInts(curr), curr)
	}
	w.WriteString("\n\n")
	w.WriteString("\toidBases = []asn1.ObjectIdentifier{\n")
	for i := len(bases) - 1; i >= 0; i-- {
		fmt.Fprintf(w, "\t\t%s,\n", oidName(bases[i].Name))
	}
	w.WriteString("\t}\n")
	w.WriteString("\n\n")
	w.WriteString("\toidNames = map[string]string{\n")
	for _, item := range all {
		fmt.Fprintf(w, "\t\t%q: %q,\n", item.ObjectIdentifier, item.Name)
	}
	w.WriteString("\t}\n")
	w.WriteString(")\n\n")
	w.WriteString(`func oidName(oid asn1.ObjectIdentifier) string {
		if s, ok := oidNames[oid.String()]; ok {
			return s
		}

		l := len(oid)
		for _, base := range oidBases {
			if n := len(base); l > n && oid[:n].Equal(base) {
				return fmt.Sprintf("id-%s-%s", oidNames[base.String()], oid[n:])
			}
		}

		return ""
}
`)

	f, err := format.Source(w.Bytes())
	if err != nil {
		panic(err)
	}

	if *output == "" || *output == "-" {
		os.Stdout.Write(f)
		return
	}

	o, err := os.Create(*output)
	if err != nil {
		panic(err)
	}
	if _, err = o.Write(f); err != nil {
		o.Close()
		panic(err)
	}
	if err = o.Close(); err != nil {
		panic(err)
	}
}

func parseObjectIdentifier(s string) (id asn1.ObjectIdentifier) {
	for _, n := range strings.Split(s, ".") {
		i, err := strconv.Atoi(n)
		if err != nil {
			panic(err)
		}
		id = append(id, i)
	}
	return
}

func oidName(s string) string {
	var (
		l        = utf8.RuneCountInString(s)
		r        = []rune("oid")
		wasSpace = true
	)
	for i, c := range s {
		if wasSpace {
			if unicode.IsNumber(c) || unicode.IsLetter(c) {
				r = append(r, unicode.ToUpper(c))
			}
			if i < l-1 && unicode.IsUpper([]rune(s)[i+1]) {
				wasSpace = true
			} else {
				wasSpace = false
			}
		} else if unicode.IsNumber(c) || unicode.IsLetter(c) {
			r = append(r, unicode.ToLower(c))
		} else if unicode.IsSpace(c) {
			wasSpace = true
		}
	}
	return string(r)
}

func oidInts(oid asn1.ObjectIdentifier) string {
	s := make([]string, len(oid))
	for i, v := range oid {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ", ")
}
