package main

import (
	ruleset "./httpse-lib"

	"fmt"
	"net/http"
	"bytes"
	"regexp"
	"io/ioutil"
	"strings"
	"encoding/xml"
	"log"
	"time"
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
 *     <target host="www.$domain" />
 * 
 *     <rule from="^http://$escaped($domain)/"
 *             to="https://$domain/" />
 * </ruleset>
 */
func trivialize_func_1(xml_ctx []byte, r ruleset.Ruleset) []byte {
	if len(r.Rules) != 1 || len(r.Targets) != 2 {
		return xml_ctx
	}

	rule_from := r.Rules[0].From
	rule_to   := r.Rules[0].To

	target1 := r.Targets[0].Host
	target2 := r.Targets[1].Host

	if "www." + target1 != target2 {
		if "www." + target2 != target1 {
			return xml_ctx
		} else {
			// swap 'target1' and 'target2'
			target1, target2 = target2, target1
		}
	}

	if rule_to != "https://" + target1 + "/" && rule_to != "https://" + target2 + "/" {
		return xml_ctx
	}

	if strings.HasSuffix(rule_from, regexp.QuoteMeta(target1) + "/") == false {
		return xml_ctx
	}

	client := &http.Client {
		Timeout: 10 * time.Second,
	}

	var err error = nil

	_, err = client.Get("https://" + target1)
	if err != nil {
		return xml_ctx
	}

	_, err = client.Get("https://" + target2)
	if err != nil {
		return xml_ctx
	}

	re := regexp.MustCompile(regex_rules)
	return re.ReplaceAllLiteral(xml_ctx, []byte(trivial_rule))
}

