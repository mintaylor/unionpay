package unionpay

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

//UnionPay unionpay
type UnionPay struct {
	Mode      string
	MerID     string
	URL       string
	FrontURL  string
	BackURL   string
	PfxPath   string
	PfxPwd    string
	UnionCert UnionCert
}

// UnionCert cert info
type UnionCert struct {
	Private *rsa.PrivateKey
	Cert    *x509.Certificate
	CertID  string
}

// NewUnionPay new unionpay client.
func NewUnionPay(unionPay UnionPay) *UnionPay {
	if err := unionPay.checkConfig(); err != nil {
		log.Fatalf("New UnionPay client error: %v", err)
		return nil
	}
	return &unionPay
}

// Post requset
func (c *UnionPay) Post(url string, m map[string]string) (map[string]string, error) {
	log.Println("sign: ", m["signature"])
	client := http.Client{}
	resp, err := client.Post(url, "application/x-www-form-urlencoded;charset=utf-8", strings.NewReader(MapURLEncode(m)))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http request response StatusCode：%v", resp.StatusCode)
	}
	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	result := c.ParseRespone(respBytes)
	if err = c.ResultCheck(result); err != nil {
		return nil, err
	}

	if ok, err := SignVerify(result); !ok && err != nil {
		return nil, err
	}
	return result, nil
}

// check UnionPay config
func (c *UnionPay) checkConfig() (err error) {
	if c.MerID == "" {
		return fmt.Errorf("MerID is empty")
	} else if c.PfxPath == "" {
		return fmt.Errorf("PfxPath is empty")
	} else if c.PfxPwd == "" {
		return fmt.Errorf("PfxPwd is empty")
	} else if c.Mode == "" {
		return fmt.Errorf("Mode is empty")
	} else if c.Mode != "dev" && c.Mode != "prod" {
		return fmt.Errorf("Mode is error: %v", c.Mode)
	}

	c.UnionCert.Private, c.UnionCert.Cert, err = ParserPfxToCert(c.PfxPath, c.PfxPwd)
	if err != nil {
		return fmt.Errorf("pfxCert error: %v", err)
	}
	c.UnionCert.CertID = fmt.Sprintf("%v", c.UnionCert.Cert.SerialNumber)
	log.Println("sign cert sn: ", c.UnionCert.CertID)
	return
}

// public params
func (c *UnionPay) publicParams() map[string]string {
	m := make(map[string]string, 0)
	m["version"] = "5.1.0"
	m["encoding"] = "utf-8"
	m["signMethod"] = "01"

	m["certId"] = c.UnionCert.CertID
	m["merId"] = c.MerID
	if c.FrontURL != "" {
		m["frontUrl"] = c.FrontURL
	}
	m["backUrl"] = c.BackURL

	if c.Mode == "dev" {
		c.URL = "https://gateway.test.95516.com"
	} else if c.Mode == "prod" {
		c.URL = "https://gateway.95516.com"
	}
	return m
}

// ParseRespone parse respone.
func (c *UnionPay) ParseRespone(bytes []byte) map[string]string {
	m := make(map[string]string, 0)
	values := strings.Split(string(bytes), "&")
	for _, v := range values {
		kv := strings.SplitN(v, "=", 2)
		m[kv[0]] = kv[1]
	}
	return m
}

// ResultCheck check result is success.
func (c *UnionPay) ResultCheck(m map[string]string) error {
	if m["respCode"] != "00" {
		return errors.New(m["respMsg"])
	}
	return nil
}

// ParseNotify parse and url decode notification.
func (c *UnionPay) ParseNotify(data string) (map[string]string, error) {
	m := make(map[string]string, 0)
	data, err := url.QueryUnescape(data)
	if err != nil {
		return nil, err
	}
	values := strings.Split(data, "&")
	for _, v := range values {
		kv := strings.SplitN(v, "=", 2)
		m[kv[0]] = kv[1]
	}
	return m, nil
}

// SortUnionMap unionpay requset map sort.
func SortUnionMap(m map[string]string) string {
	var keys, str []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k != "signature" {
			str = append(str, k+"="+m[k])
		}
	}
	return strings.Join(str, "&")
}

// MapURLEncode Map to string and url encode.
func MapURLEncode(m map[string]string) string {
	qs := url.Values{}
	for k, v := range m {
		qs.Add(k, v)
	}
	return qs.Encode()
}

// AppConsume 消费获取Tn
func (c *UnionPay) AppConsume(txnamt int, orderNo, attach string) (map[string]string, error) {
	m := c.publicParams()
	m["txnType"] = "01"
	m["txnSubType"] = "01"
	m["bizType"] = "000201"
	m["channelType"] = "08"
	m["accessType"] = "0"
	m["currencyCode"] = "156"

	m["orderId"] = orderNo
	m["txnTime"] = time.Now().Format("20060102150405")
	m["txnAmt"] = fmt.Sprintf("%d", txnamt)
	if attach != "" {
		m["reqReserved"] = base64.StdEncoding.EncodeToString([]byte(attach))
	}
	m["signature"], _ = Sign(m, c.UnionCert.Private)
	return c.Post(c.URL+"/gateway/api/appTransReq.do", m)
}

// ConsumeUndo 消费撤销交易
func (c *UnionPay) ConsumeUndo(txnamt int, orderNo, queryID, attach string) (map[string]string, error) {
	m := c.publicParams()
	delete(m, "frontUrl")
	m["txnType"] = "31"
	m["txnSubType"] = "00"
	m["bizType"] = "000201"
	m["channelType"] = "07"
	m["accessType"] = "0"

	m["orderId"] = orderNo
	m["origQryId"] = queryID
	m["txnTime"] = time.Now().Format("20060102150405")
	m["txnAmt"] = fmt.Sprintf("%d", txnamt)
	if attach != "" {
		m["reqReserved"] = base64.StdEncoding.EncodeToString([]byte(attach))
	}
	m["signature"], _ = Sign(m, c.UnionCert.Private)
	return c.Post(c.URL+"/gateway/api/backTransReq.do", m)
}

// Refund 退货交易
func (c *UnionPay) Refund(txnamt int, orderNo, queryID, attach string) (map[string]string, error) {
	m := c.publicParams()
	delete(m, "frontUrl")
	m["txnType"] = "04"
	m["txnSubType"] = "00"
	m["bizType"] = "000201"
	m["channelType"] = "07"
	m["accessType"] = "0"

	m["orderId"] = orderNo
	m["origQryId"] = queryID
	m["txnTime"] = time.Now().Format("20060102150405")
	m["txnAmt"] = fmt.Sprintf("%d", txnamt)
	if attach != "" {
		m["reqReserved"] = base64.StdEncoding.EncodeToString([]byte(attach))
	}
	m["signature"], _ = Sign(m, c.UnionCert.Private)
	return c.Post(c.URL+"/gateway/api/backTransReq.do", m)
}

// Query 交易状态查询
func (c *UnionPay) Query(orderNo string) (map[string]string, error) {
	m := c.publicParams()
	delete(m, "frontUrl")
	delete(m, "backUrl")
	m["txnType"] = "00"
	m["txnSubType"] = "00"
	m["bizType"] = "000000"
	m["channelType"] = "07"
	m["accessType"] = "0"

	m["orderId"] = orderNo
	m["txnTime"] = time.Now().Format("20060102150405")
	m["signature"], _ = Sign(m, c.UnionCert.Private)
	return c.Post(c.URL+"/gateway/api/queryTrans.do", m)
}
