package main

import (
	ruleset "./httpse-lib"

	"fmt"
	"bytes"
	"regexp"
	"io/ioutil"
	"strings"
	"encoding/xml"
	"sort"
	"log"
	"os"
	"path/filepath"
)

// regex to remove rule
var regex_rules = `<rule\s+from=\s*"[^"]+"\s+to=\s*"[^"]+"\s*/>`

// regex to remove target
var regex_targe = `<target\s+host=\s*"[^"]+"\s*/>`

// sample trivial rule
var trivial_rule = `<rule from="^http:" to="https:" />`

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: TDRRs path-to-https-everywhere/rules")
		os.Exit(1)
	}

	// read file from path-to-https-everywhere/rules
	files, err := ioutil.ReadDir(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// number of files modified
	num_changes := 0

	// iterate through *.xml
	for _, file := range files {
		fn := file.Name()
		fp := filepath.Join(os.Args[1], fn)

		// assert the file extension is '.xml'
		if strings.HasSuffix(fn, ".xml") == false {
			log.Printf("Skipping %s", fn)
			continue
		}

		// read file into memory
		xml_ctx, err := ioutil.ReadFile(fp)
		if err != nil {
			log.Print(err)
			continue
		}

		var r ruleset.Ruleset
		xml.Unmarshal(xml_ctx, &r)

		// ignore default_off ruleset (optional yet prefered)
		if len(r.Default_off) > 0 {
			continue
		}

		// no exclusion
		if len(r.Exclusions) != 0 {
			continue
		}

		// modified xml content
		m_xml := xml_ctx

		// an array of func to apply on xml_content
		trivialize_func := [1]func([]byte, ruleset.Ruleset) []byte {
			trivialize_func_1,
			// trivialize_func_2,
			// trivialize_func_3,
		}

		for _, tf := range trivialize_func {
			if m_xml = tf(xml_ctx, r); bytes.Compare(m_xml, xml_ctx) != 0 {
				err := ioutil.WriteFile(fp, []byte(m_xml), 0644)
				if err != nil {
					log.Print(err)
				} else {
					num_changes++
				}
			}
		}
	}
	log.Printf("Rewritten %d files", num_changes)
}

/* Example.com.xml
 * 
 * <ruleset name="Example.com">
 *     <target host="$domain" />
 * 
 *     <rule from="^http://$escaped($domain)/"
 *             to="https://$domain/" />
 * </ruleset>
 */
func trivialize_func_1(xml_ctx []byte, r ruleset.Ruleset) []byte {
	// only works when #rule == #non-wildcard target == 1
	if len(r.Rules) != 1 || len(r.Targets) != 1 {
		return xml_ctx
	}

	target := r.Targets[0].Host
	from   := r.Rules[0].From
	to     := r.Rules[0].To

	// no wildcard
	if strings.Contains(target, "*") {
		return xml_ctx
	}

	tfrom := "^http://" + regexp.QuoteMeta(target) + "/"
	tto   := "https://" + target + "/"

	if from == tfrom && to == tto {
		re := regexp.MustCompile(regex_rules)
		return re.ReplaceAllLiteral(xml_ctx, []byte(trivial_rule))
	}
	return xml_ctx
}

/* Example.net.xml
 * 
 * <ruleset name="Example.net">
 *     <target host="*.$domain" />
 * 
 *     <rule from="^http://(sub1|sub2)\.$escaped($domain)/"
 *             to="https://$1.$domain/" />
 * </ruleset>
 */
func trivialize_func_2(xml_ctx []byte, r ruleset.Ruleset) []byte {
	// only works when #rule == #non-wildcard target == 1
	if len(r.Rules) != 1 || len(r.Targets) != 1 {
		return xml_ctx
	}

	target := r.Targets[0].Host
	from   := r.Rules[0].From
	to     := r.Rules[0].To

	if strings.Count(target, "*") != 1 {
		return xml_ctx
	}

	if strings.HasPrefix(target, "*.") == false {
		return xml_ctx
	} else {
		target = target[2:len(target)]
	}

	// check `to`
	if to != `https://$1.` + target + `/` {
		return xml_ctx
	}

	// check `from`
	rfrp := `^\^http://\((\?:)?([\w-]+\|?)+\)\\.`
	rfrm := strings.Replace(regexp.QuoteMeta(target), `\`, `\\`, -1)
	rfrs := `/$`

	re := regexp.MustCompile(rfrp + rfrm + rfrs)
	if re.MatchString(from) == false {
		return xml_ctx
	}

	// extract `prefix`
	foo := ``
	trivial_target := ``


	start := strings.Index(from, `(`) + 1
	end   := strings.Index(from, `)`)

	if start >= end {
		return xml_ctx
	} else {
		foo = from[start:end]
		foo = strings.Replace(foo, "?:", "", -1)
	}

	bar := strings.Split(foo, "|")
	sort.Strings(bar)

	if len(bar) == 0 {
		return xml_ctx
	}

	for _, prefix := range bar {
		tmp := `<target host="` + prefix + `.` + target + `" />` + "\n\t"
		trivial_target += tmp
	}

	// remove tailing `\n\t`
	trivial_target = trivial_target[0:len(trivial_target) - 2]

	// output xml
	m_xml := xml_ctx

	// rewrite `rule`
	if true {
		re := regexp.MustCompile(regex_rules)
		m_xml = re.ReplaceAllLiteral(m_xml, []byte(trivial_rule))

		if bytes.Compare(m_xml, xml_ctx) == 0 {
			// unsuccessful rewrite
			return xml_ctx
		}
	}

	// rewrite `target`
	if true {
		re := regexp.MustCompile(regex_targe)
		m_xml = re.ReplaceAllLiteral(m_xml, []byte(trivial_target))

		if bytes.Compare(m_xml, xml_ctx) == 0 {
			// unsuccessful rewrite
			return xml_ctx
		}
	}
	return m_xml
}

/* Example.org.xml
 * 
 * <ruleset name="Example.org">
 *     <target host="$domain" />
 *     <target host="*.$domain" />
 * 
 *     <rule from="^http://(sub1\.|sub2\.)?$escaped($domain)/"
 *             to="https://$1$domain/" />
 * </ruleset>
 */
func trivialize_func_3(xml_ctx []byte, r ruleset.Ruleset) []byte {
	if len(r.Rules) != 1 {
	// if len(r.Rules) != 1 || len(r.Targets) != 2 {
		return xml_ctx
	}

	target := r.Targets[0].Host
	from   := r.Rules[0].From
	to     := r.Rules[0].To

	// if `*.` + r.Targets[0].Host != r.Targets[1].Host {
	//	return xml_ctx
	// }

	// check `to`
	if to != `https://$1` + target + `/` {
		return xml_ctx
	}

	// check `from`
	rfrp := `^\^http://\((\?:)?([\w-]+\\.\|?)+\)\?`
	rfrm := strings.Replace(regexp.QuoteMeta(target), `\`, `\\`, -1)
	rfrs := `/$`

	re := regexp.MustCompile(rfrp + rfrm + rfrs)
	if re.MatchString(from) == false {
		return xml_ctx
	}

	// extract `prefix`
	foo := ``
	trivial_target := ``

	start := strings.Index(from, `(`) + 1
	end   := strings.Index(from, `)`)

	if start >= end {
		return xml_ctx
	} else {
		foo = from[start:end]
		foo = strings.Replace(foo, "?:", "", -1)
		foo = strings.Replace(foo, `\.`, ".", -1)
	}

	bar := strings.Split(foo, "|")
	bar = append(bar, "")
	sort.Strings(bar)

	if len(bar) == 0 {
		return xml_ctx
	}

	for _, prefix := range bar {
		tmp := `<target host="` + prefix + target + `" />` + "\n\t"
		trivial_target += tmp
	}

	// remove tailing `\n\t`
	trivial_target = trivial_target[0:len(trivial_target) - 2]

	// output xml
	m_xml := xml_ctx

	// rewrite `rule`
	if true {
		re := regexp.MustCompile(regex_rules)
		m_xml = re.ReplaceAllLiteral(m_xml, []byte(trivial_rule))

		if bytes.Compare(m_xml, xml_ctx) == 0 {
			// unsuccessful rewrite
			return xml_ctx
		}
	}

	// rewrite `target`
	if true {
		re := regexp.MustCompile(regex_targe)
		m_xml = re.ReplaceAllLiteral(m_xml, []byte(trivial_target))
		m_xml = []byte(strings.Replace(string(m_xml), trivial_target, "", 1))

		if bytes.Compare(m_xml, xml_ctx) == 0 {
			// unsuccessful rewrite
			return xml_ctx
		}
	}
	return m_xml
}
