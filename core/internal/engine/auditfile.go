package engine

import "github.com/sumukhak/new-genadb/core/pkg/genadb/audit"

func openAuditFile(path string) (audit.Sink, error) { return audit.OpenFile(path, false) }
