package genadb_test

import (
	"testing"

	"github.com/sumukhak/new-genadb/core/pkg/genadb"
)

// v1.0.1 renamed Client and Session to SetuClient and SetuSession. Code
// written against 1.0.0 must compile unchanged and get the same types.
func TestPre101NamesStillWork(t *testing.T) {
	var old *genadb.Client
	var cur *genadb.SetuClient = old // same type: no conversion needed
	_ = cur

	c, err := genadb.New(genadb.WithStateDir(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var asOld *genadb.Client = c
	var sessions []*genadb.Session = asOld.Sessions()
	var setuSessions []*genadb.SetuSession = sessions
	if len(setuSessions) != 0 {
		t.Fatal("new client has sessions")
	}
	if _, ok := asOld.Session("missing"); ok {
		t.Fatal("unknown session found")
	}
}
