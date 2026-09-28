package coraza_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"gopkg.in/yaml.v3"
)

// Read the same FTW requests used by the ModSecurity compatibility matrix.
// This suite additionally checks the complete request anomaly decision at PL1.
type fixture struct {
	RuleID int `yaml:"rule_id"`
	Tests  []struct {
		ID     int `yaml:"test_id"`
		Stages []struct {
			Input struct {
				Method  string            `yaml:"method"`
				URI     string            `yaml:"uri"`
				Headers map[string]string `yaml:"headers"`
				Data    string            `yaml:"data"`
			} `yaml:"input"`
			Output struct {
				Log struct {
					Expect   []int `yaml:"expect_ids"`
					NoExpect []int `yaml:"no_expect_ids"`
				} `yaml:"log"`
			} `yaml:"output"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}

func TestPlugin(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	crs := os.Getenv("CRS_DIR")
	if crs == "" {
		t.Fatal("set CRS_DIR to the CRS 4.29.0 checkout")
	}
	crs, err = filepath.Abs(crs)
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "tests/regression/ocis-rule-exclusions/*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, disabled := range []bool{false, true} {
		name := "enabled"
		disable := ""
		if disabled {
			name = "disabled"
			disable = `SecAction "id:1000000,phase:1,pass,nolog,setvar:'tx.ocis-rule-exclusions-plugin_enabled=0'"`
		}
		t.Run(name, func(t *testing.T) {
			directives := fmt.Sprintf(`
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecAuditEngine Off
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body'"
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1"
%s
Include %s/crs-setup.conf.example
Include %s/plugins/*-config.conf
Include %s/plugins/*-before.conf
Include %s/rules/*.conf
Include %s/plugins/*-after.conf
`, disable, crs, root, root, crs, root)
			waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, file := range files {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				var f fixture
				if err = yaml.Unmarshal(data, &f); err != nil {
					t.Fatal(err)
				}
				for _, tc := range f.Tests {
					// Controls prove the affected detectors work when the plugin is disabled.
					controlID := 0
					if disabled {
						if tc.ID != 1 {
							continue
						}
						switch f.RuleID {
						case 9542202:
							controlID = 930120
						case 9542203:
							controlID = 942100
						case 9542204:
							controlID = 920420
						default:
							continue
						}
					}
					count++
					t.Run(fmt.Sprintf("%d-%d", f.RuleID, tc.ID), func(t *testing.T) {
						if len(tc.Stages) != 1 {
							t.Fatal("runner supports single-stage FTW tests only")
						}
						st := tc.Stages[0]
						tx := waf.NewTransaction()
						defer tx.Close()
						tx.ProcessConnection("127.0.0.1", 12345, "127.0.0.1", 80)
						tx.ProcessURI(st.Input.URI, st.Input.Method, "HTTP/1.1")
						for k, v := range st.Input.Headers {
							tx.AddRequestHeader(k, v)
						}
						if st.Input.Data != "" {
							tx.AddRequestHeader("Content-Length", strconv.Itoa(len(st.Input.Data)))
						}
						tx.ProcessRequestHeaders()
						if _, _, err := tx.WriteRequestBody([]byte(st.Input.Data)); err != nil {
							t.Fatal(err)
						}
						if _, err := tx.ProcessRequestBody(); err != nil {
							t.Fatal(err)
						}
						ids := map[int]bool{}
						for _, m := range tx.MatchedRules() {
							ids[m.Rule().ID()] = true
						}
						defer func() {
							if t.Failed() {
								t.Logf("matched rules: %v", ids)
							}
						}()
						if disabled {
							if !ids[controlID] || !ids[949110] {
								t.Errorf("disabled plugin must trigger %d and 949110", controlID)
							}
							return
						}
						for _, id := range st.Output.Log.Expect {
							if !ids[id] {
								t.Errorf("expected rule %d", id)
							}
						}
						for _, id := range st.Output.Log.NoExpect {
							if ids[id] {
								t.Errorf("unexpected rule %d", id)
							}
						}
						if len(st.Output.Log.NoExpect) > 0 {
							for _, id := range []int{949110, 200002} {
								if ids[id] {
									t.Errorf("legitimate PL1 request rejected by %d", id)
								}
							}
						}
					})
				}
			}
			if count == 0 {
				t.Fatal("no tests executed")
			}
		})
	}
}
