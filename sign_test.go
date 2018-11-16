package wechataes

import (
    "testing"
)

var expectSHA1 = "82c962d39941aa48552f90ef55aa323dc620cc10"

func TestSHA1(t *testing.T) {
    sha1 := SHA1(token, timestamp, nonce, afterAesEncrypt)
    if expectSHA1 != sha1 {
        t.Error("no异常")
    }
}
