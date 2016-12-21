// Copyright 2016 Keybase Inc. All rights reserved.
// Use of this source code is governed by a BSD
// license that can be found in the LICENSE file.

package libfuse

import "bazil.org/fuse"

func wrapErrorForBazil(err error) error {
	if err == nil {
		return nil
	}

	return errorWithNumber{err}
}

type errorWithNumber struct {
	err error
}

var _ error = errorWithNumber{}
var _ fuse.ErrorNumber = errorWithNumber{}

func (e errorWithNumber) Error() string {
	return e.err.Error()
}

func (e errorWithNumber) Errno() fuse.Errno {
	if errNumber, ok := e.err.(fuse.ErrorNumber); ok {
		return errNumber.Errno()
	}
	return fuse.DefaultErrno
}
