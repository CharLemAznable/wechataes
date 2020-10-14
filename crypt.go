package wechataes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	mathRand "math/rand"
	"time"
)

type WechatCryptor struct {
	appId  string
	token  string
	aesKey []byte
}

// 构造函数
// appId 公众平台appid
// token 公众平台上，开发者设置的token
// aesKey 公众平台上，开发者设置的EncodingAESKey
func NewWechatCryptor(appId, token, encodingAesKey string) (*WechatCryptor, error) {
	cryptor := new(WechatCryptor)
	if 43 != len(encodingAesKey) {
		return cryptor, &WechatCryptorError{Code: IllegalAesKey}
	}
	cryptor.appId = appId
	cryptor.token = token
	cryptor.aesKey, _ = base64.StdEncoding.DecodeString(encodingAesKey + "=")
	return cryptor, nil
}

func (cryptor *WechatCryptor) String() string {
	return "AppId(" + cryptor.appId +
		") Token(" + cryptor.token +
		") AES_KEY(" + base64.StdEncoding.EncodeToString(cryptor.aesKey) + ")"
}

// 随机生成16位字符串
func WechatCryptorRandomStr() string {
	r := mathRand.New(mathRand.NewSource(time.Now().UnixNano()))
	bytes := []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var result []byte
	for i := 0; i < 16; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

const WechatCryptorEncryptMsgFormat = `
<xml>
<Encrypt><![CDATA[%s]]></Encrypt>
<MsgSignature><![CDATA[%s]]></MsgSignature>
<TimeStamp>%s</TimeStamp>
<Nonce><![CDATA[%s]]></Nonce>
</xml>
`

func (cryptor *WechatCryptor) EncryptMsg(msg, timeStamp, nonce string) (string, error) {
	encrypt, sign, timeStamp, nonce, err := cryptor.EncryptMsgContent(msg, timeStamp, nonce)
	if nil != err {
		return "", err
	}
	return fmt.Sprintf(WechatCryptorEncryptMsgFormat, encrypt, sign, timeStamp, nonce), nil
}

type WechatCryptorPostBody struct {
	XMLName    xml.Name `xml:"xml"`
	ToUserName string   `xml:"ToUserName"`
	AppId      string   `xml:"AppId"`
	Encrypt    string   `xml:"Encrypt"`
}

func (cryptor *WechatCryptor) DecryptMsg(msgSign, timeStamp, nonce, postData string) (string, error) {
	postBody := WechatCryptorPostBody{}
	err := xml.Unmarshal([]byte(postData), &postBody)
	if nil != err || 0 == len(postBody.Encrypt) {
		return "", &WechatCryptorError{Code: ParseXmlError}
	}

	return cryptor.DecryptMsgContent(msgSign, timeStamp, nonce, postBody.Encrypt)
}

func (cryptor *WechatCryptor) EncryptMsgContent(msg, timeStamp, nonce string) (string, string, string, string, error) {
	encrypt, err := cryptor.Encrypt(WechatCryptorRandomStr(), msg)
	if nil != err {
		return "", "", "", "", err
	}

	if 0 == len(timeStamp) {
		timeStamp = fmt.Sprint(time.Now().Unix())
	}

	sign := SHA1(cryptor.token, timeStamp, nonce, encrypt)
	return encrypt, sign, timeStamp, nonce, nil
}

func (cryptor *WechatCryptor) DecryptMsgContent(msgSign, timeStamp, nonce, encrypt string) (string, error) {
	sign := SHA1(cryptor.token, timeStamp, nonce, encrypt)
	if msgSign != sign {
		return "", &WechatCryptorError{Code: ValidateSignatureError}
	}

	return cryptor.Decrypt(encrypt)
}

// 对明文进行加密
func (cryptor *WechatCryptor) Encrypt(randomStr, text string) (string, error) {
	randomBytes := []byte(randomStr)
	textBytes := []byte(text)
	networkBytes := wechatCryptorBuildNetworkBytesOrder(len(textBytes))
	appIdBytes := []byte(cryptor.appId)
	var unencrypted []byte
	unencrypted = append(unencrypted, randomBytes...)
	unencrypted = append(unencrypted, networkBytes...)
	unencrypted = append(unencrypted, textBytes...)
	unencrypted = append(unencrypted, appIdBytes...)
	encrypted, err := wechatCryptorEncrypt(unencrypted, cryptor.aesKey)
	if nil != err {
		return "", &WechatCryptorError{Code: EncryptAESError}
	}
	return encrypted, nil
}

// 对密文进行解密
func (cryptor *WechatCryptor) Decrypt(text string) (string, error) {
	original, err := wechatCryptorDecrypt(text, cryptor.aesKey)
	if nil != err {
		return "", &WechatCryptorError{Code: DecryptAESError}
	}
	networkBytes := original[16:20]
	textLen := wechatCryptorRecoverNetworkBytesOrder(networkBytes)
	textBytes := original[20 : 20+textLen]
	appIdBytes := original[20+textLen:]
	if cryptor.appId != string(appIdBytes) {
		return "", &WechatCryptorError{Code: ValidateAppidError}
	}
	return string(textBytes), nil
}

func wechatCryptorEncrypt(rawData, key []byte) (string, error) {
	data, err := wechatCryptorAesCBCEncrypt(rawData, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func wechatCryptorDecrypt(rawData string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(rawData)
	if err != nil {
		return nil, err
	}
	dnData, err := wechatCryptorAesCBCDecrypt(data, key)
	if err != nil {
		return nil, err
	}
	return dnData, nil
}

// aes加密，填充秘钥key的16位
func wechatCryptorAesCBCEncrypt(rawData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 填充原文
	rawData = wechatCryptorPKCS7Padding(rawData)
	cipherText := make([]byte, len(rawData))
	// 初始向量IV
	iv := key[:16]

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, rawData)

	return cipherText, nil
}

// aes解密
func wechatCryptorAesCBCDecrypt(encryptData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 初始向量IV
	iv := key[:16]
	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(encryptData, encryptData)
	// 解填充
	encryptData = wechatCryptorPKCS7UnPadding(encryptData)
	return encryptData, nil
}

func wechatCryptorPKCS7Padding(ciphertext []byte) []byte {
	amountToPad := 32 - (len(ciphertext) % 32)
	if 0 == amountToPad {
		amountToPad = 32
	}
	padChr := (byte)(amountToPad & 0xFF)
	result := make([]byte, len(ciphertext), len(ciphertext)+amountToPad)
	copy(result, ciphertext)
	for i := 0; i < amountToPad; i++ {
		result = append(result, padChr)
	}
	return result
}

func wechatCryptorPKCS7UnPadding(origData []byte) []byte {
	pad := (int)(origData[len(origData)-1])
	if pad < 1 || pad > 32 {
		pad = 0
	}
	return origData[:len(origData)-pad]
}

// 生成4个字节的网络字节序
func wechatCryptorBuildNetworkBytesOrder(number int) []byte {
	return []byte{
		(byte)(number >> 24 & 0xFF),
		(byte)(number >> 16 & 0xF),
		(byte)(number >> 8 & 0xFF),
		(byte)(number & 0xFF),
	}
}

// 还原4个字节的网络字节序
func wechatCryptorRecoverNetworkBytesOrder(orderBytes []byte) int {
	var number = 0
	for i := 0; i < 4; i++ {
		number <<= 8
		number |= (int)(orderBytes[i] & 0xff)
	}
	return number
}

/**
异常的错误码和具体的错误信息
*/
type WechatCryptorError struct {
	Code int
}

const OK int = 0
const ValidateSignatureError int = -40001
const ParseXmlError int = -40002
const ComputeSignatureError int = -40003
const IllegalAesKey int = -40004
const ValidateAppidError int = -40005
const EncryptAESError int = -40006
const DecryptAESError int = -40007
const IllegalBuffer int = -40008

func (e *WechatCryptorError) Error() string {
	switch e.Code {
	case ValidateSignatureError:
		return "签名验证错误"
	case ParseXmlError:
		return "xml解析失败"
	case ComputeSignatureError:
		return "sha加密生成签名失败"
	case IllegalAesKey:
		return "SymmetricKey非法"
	case ValidateAppidError:
		return "appid校验失败"
	case EncryptAESError:
		return "aes加密失败"
	case DecryptAESError:
		return "aes解密失败"
	case IllegalBuffer:
		return "解密后得到的buffer非法"
	default:
		return ""
	}
}
