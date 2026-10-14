package ui

import (
	"os/exec"
	"strings"
	"testing"
)

// A page opened without the readiness link's fragment, or from a stale tab,
// gets 401 on every data route; it must say which link to open rather than
// render empty chrome.
func TestPageExplainsAMissingCapability(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required for page JavaScript regression tests")
	}
	cmd := exec.Command(node, "-e", `
const assert=require('node:assert/strict'),vm=require('node:vm');
const html=require('node:fs').readFileSync(0,'utf8');
let source=html.split('<script>')[1].split('</script>')[0];
source=source.replace('(async () => { renderChrome(); await loadRepos(); renderChrome(); await refresh(true); schedule(); })();','globalThis.loadRepos=loadRepos;');
const elements=new Map();
const element=id=>{ if(!elements.has(id)) elements.set(id,{id,hidden:true,textContent:'',addEventListener(){},querySelector(){return null;}}); return elements.get(id); };
const context=vm.createContext({URLSearchParams,
 window:{addEventListener(){},location:{hash:'',pathname:'/',search:''},history:{replaceState(){}}},
 sessionStorage:{getItem:()=>null,setItem(){}},
 document:{documentElement:{},getElementById:element},
 fetch:()=>Promise.resolve({ok:false,status:401}),setTimeout(){},clearTimeout(){}
});
vm.runInContext(source,context);
context.loadRepos().then(()=>{
  const note=element('access-note');
  assert.equal(note.hidden,false);
  assert.ok(note.textContent.includes('unauthorized')||note.textContent.includes('access'), note.textContent);
});
`)
	cmd.Stdin = strings.NewReader(pageHTML)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("page access-note regression: %v\n%s", err, output)
	}
}
