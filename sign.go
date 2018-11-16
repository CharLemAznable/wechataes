package wechataes

import (
    "crypto/sha1"
    "encoding/hex"
    "sort"
    "strings"
)

func SHA1(token, timestamp, nonce, encrypt string) string {
    array := []string{token, timestamp, nonce, encrypt}
    sort.Strings(array)
    str := strings.Join(array, "")

    hash := sha1.New()
    hash.Write([]byte(str))
    sum := hash.Sum(nil)
    sumHex := make([]byte, hex.EncodedLen(len(sum)))
    hex.Encode(sumHex, sum)
    return string(sumHex)
}
