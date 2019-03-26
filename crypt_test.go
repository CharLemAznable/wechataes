package wechataes

import (
    "encoding/xml"
    "fmt"
    "testing"
)

var appId = "wxb11529c136998cb6"
var token = "pamtest"
var encodingAesKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
var randomStr = "aaaabbbbccccdddd"
var replyMsg = "我是中文abcd123"
var afterAesEncrypt = "jn1L23DB+6ELqJ+6bruv21Y6MD7KeIfP82D6gU39rmkgczbWwt5+3bnyg5K55bgVtVzd832WzZGMhkP72vVOfg=="
var replyMsg2 = "<xml><ToUserName><![CDATA[oia2Tj我是中文jewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType><![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Description><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>"
var afterAesEncrypt2 = "jn1L23DB+6ELqJ+6bruv23M2GmYfkv0xBh2h+XTBOKVKcgDFHle6gqcZ1cZrk3e1qjPQ1F4RsLWzQRG9udbKWesxlkupqcEcW7ZQweImX9+wLMa0GaUzpkycA8+IamDBxn5loLgZpnS7fVAbExOkK5DYHBmv5tptA9tklE/fTIILHR8HLXa5nQvFb3tYPKAlHF3rtTeayNf0QuM+UW/wM9enGIDIJHF7CLHiDNAYxr+r+OrJCmPQyTy8cVWlu9iSvOHPT/77bZqJucQHQ04sq7KZI27OcqpQNSto2OdHCoTccjggX5Z9Mma0nMJBU+jLKJ38YB1fBIz+vBzsYjrTmFQ44YfeEuZ+xRTQwr92vhA9OxchWVINGC50qE/6lmkwWTwGX9wtQpsJKhP+oS7rvTY8+VdzETdfakjkwQ5/Xka042OlUb1/slTwo4RscuQ+RdxSGvDahxAJ6+EAjLt9d8igHngxIbf6YyqqROxuxqIeIch3CssH/LqRs+iAcILvApYZckqmA7FNERspKA5f8GoJ9sv8xmGvZ9Yrf57cExWtnX8aCMMaBropU/1k+hKP5LVdzbWCG0hGwx/dQudYR/eXp3P0XxjlFiy+9DMlaFExWUZQDajPkdPrEeOwofJb"
var timestamp = "1409304348"
var nonce = "xxxxxx"

func TestWechatCrypt(t *testing.T) {
    cryptor, _ := NewWechatCryptor(appId, token, encodingAesKey)
    if "AppId(wxb11529c136998cb6) Token(pamtest) AES_KEY(abcdefghijklmnopqrstuvwxyz0123456789ABCDEFE=)" != cryptor.String() {
        t.Error("no异常")
    }

    encrypt, _ := cryptor.Encrypt(randomStr, replyMsg)
    if afterAesEncrypt != encrypt {
        t.Error("no异常")
    }
    decrypt, _ := cryptor.Decrypt(afterAesEncrypt)
    if replyMsg != decrypt {
        t.Error("no异常")
    }

    encrypt2, _ := cryptor.Encrypt(randomStr, replyMsg2)
    if afterAesEncrypt2 != encrypt2 {
        t.Error("no异常")
    }
    decrypt2, _ := cryptor.Decrypt(afterAesEncrypt2)
    if replyMsg2 != decrypt2 {
        t.Error("no异常")
    }
}

type TestEncryptMsg struct {
    XMLName      xml.Name `xml:"xml"`
    Encrypt      string   `xml:"Encrypt"`
    MsgSignature string   `xml:"MsgSignature"`
}

func TestWechatCryptMsg(t *testing.T) {
    cryptor, _ := NewWechatCryptor(appId, token, encodingAesKey)
    afterEncrpt, _ := cryptor.EncryptMsg(replyMsg, timestamp, nonce)

    encryptMsg := TestEncryptMsg{}
    _ = xml.Unmarshal([]byte(afterEncrpt), &encryptMsg)
    format := "<xml><ToUserName><![CDATA[toUser]]></ToUserName><Encrypt><![CDATA[%s]]></Encrypt></xml>"
    fromXML := fmt.Sprintf(format, encryptMsg.Encrypt)

    afterDecrpt, _ := cryptor.DecryptMsg(encryptMsg.MsgSignature, timestamp, nonce, fromXML)
    if replyMsg != afterDecrpt {
        t.Error("no异常")
    }
}

func TestError(t *testing.T) {
    _, err := NewWechatCryptor(appId, token, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF")
    if "SymmetricKey非法" != err.Error() {
        t.Error("encodingAesKey异常")
    }

    err = &WechatCryptorError{Code: ValidateSignatureError}
    if "签名验证错误" != err.Error() {
        t.Error("no异常")
    }

    err = &WechatCryptorError{Code: ParseXmlError}
    if "xml解析失败" != err.Error() {
        t.Error("no异常")
    }

    err = &WechatCryptorError{Code: ComputeSignatureError}
    if "sha加密生成签名失败" != err.Error() {
        t.Error("no异常")
    }

    err = &WechatCryptorError{Code: ValidateAppidError}
    if "appid校验失败" != err.Error() {
        t.Error("no异常")
    }

    err = &WechatCryptorError{Code: EncryptAESError}
    if "aes加密失败" != err.Error() {
        t.Error("no异常")
    }

    err = &WechatCryptorError{Code: DecryptAESError}
    if "aes解密失败" != err.Error() {
        t.Error("no异常")
    }

    err = &WechatCryptorError{Code: IllegalBuffer}
    if "解密后得到的buffer非法" != err.Error() {
        t.Error("no异常")
    }
}
