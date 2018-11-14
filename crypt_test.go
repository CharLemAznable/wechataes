package wechataes

import (
    "fmt"
    "testing"
)

var appId = "wxb11529c136998cb6"
var token = "pamtest"
var encodingAesKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
var randomStr = "aaaabbbbccccdddd"
var replyMsg = "我是中文abcd123"
var afterAesEncrypt = "jn1L23DB+6ELqJ+6bruv21Y6MD7KeIfP82D6gU39rmkgczbWwt5+3bnyg5K55bgVtVzd832WzZGMhkP72vVOfg=="
var replyMsg2 = "<xml><ToUserName><![CDATA[oia2Tj我是中文jewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType><![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Description><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>";
var afterAesEncrypt2 = "jn1L23DB+6ELqJ+6bruv23M2GmYfkv0xBh2h+XTBOKVKcgDFHle6gqcZ1cZrk3e1qjPQ1F4RsLWzQRG9udbKWesxlkupqcEcW7ZQweImX9+wLMa0GaUzpkycA8+IamDBxn5loLgZpnS7fVAbExOkK5DYHBmv5tptA9tklE/fTIILHR8HLXa5nQvFb3tYPKAlHF3rtTeayNf0QuM+UW/wM9enGIDIJHF7CLHiDNAYxr+r+OrJCmPQyTy8cVWlu9iSvOHPT/77bZqJucQHQ04sq7KZI27OcqpQNSto2OdHCoTccjggX5Z9Mma0nMJBU+jLKJ38YB1fBIz+vBzsYjrTmFQ44YfeEuZ+xRTQwr92vhA9OxchWVINGC50qE/6lmkwWTwGX9wtQpsJKhP+oS7rvTY8+VdzETdfakjkwQ5/Xka042OlUb1/slTwo4RscuQ+RdxSGvDahxAJ6+EAjLt9d8igHngxIbf6YyqqROxuxqIeIch3CssH/LqRs+iAcILvApYZckqmA7FNERspKA5f8GoJ9sv8xmGvZ9Yrf57cExWtnX8aCMMaBropU/1k+hKP5LVdzbWCG0hGwx/dQudYR/eXp3P0XxjlFiy+9DMlaFExWUZQDajPkdPrEeOwofJb"

func TestNewWechatCryptor(t *testing.T) {
    cryptor, _ := NewWechatCryptor(appId, token, encodingAesKey)
    encrypt, _ := cryptor.Encrypt(randomStr, replyMsg)
    fmt.Println(encrypt)
    if afterAesEncrypt != encrypt {
        t.Error("no异常")
    }
    decrypt, _ := cryptor.Decrypt(afterAesEncrypt)
    fmt.Println(decrypt)
    if replyMsg != decrypt {
        t.Error("no异常")
    }

    encrypt2, _ := cryptor.Encrypt(randomStr, replyMsg2)
    fmt.Println(encrypt2)
    if afterAesEncrypt2 != encrypt2 {
        t.Error("no异常")
    }
    decrypt2, _ := cryptor.Decrypt(afterAesEncrypt2)
    fmt.Println(decrypt2)
    if replyMsg2 != decrypt2 {
        t.Error("no异常")
    }
}
