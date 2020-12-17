package unionpay

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
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
	apiurl    string
	apiaddr   string
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
	}
	return &unionPay
}

// Post requset
func (c *UnionPay) Post(m map[string]string) (map[string]string, error) {
	contentType := "application/x-www-form-urlencoded;charset=utf-8"
	client := http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				c, err := net.DialTimeout(netw, addr, time.Second*5)
				if err != nil {
					log.Println("dail timeout", err)
					return nil, err
				}
				return c, nil
			},
			MaxIdleConnsPerHost:   10,
			ResponseHeaderTimeout: time.Second * 3,
		},
	}
	resp, err := client.Post(c.apiurl, contentType, strings.NewReader(MapURLEncode(m)))
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
func (c *UnionPay) publicParams(m map[string]string) map[string]string {
	m["version"] = "5.1.0"
	m["encoding"] = "utf-8"
	m["signMethod"] = "01"

	m["certId"] = c.UnionCert.CertID
	m["merId"] = c.MerID
	if c.FrontURL != "" && m["frontUrl"] != "0" {
		m["frontUrl"] = c.FrontURL
	}
	if m["backUrl"] != "0" {
		m["backUrl"] = c.BackURL
	}

	switch c.Mode {
	case "prod":
		c.URL = "https://gateway.95516.com"
	case "dev":
		c.URL = "https://gateway.test.95516.com"
	}
	c.apiurl = c.URL + c.apiaddr

	m["txnTime"] = time.Now().Format("20060102150405")
	sign, err := Sign(m, c.UnionCert.Private)
	if err != nil {
		log.Fatalf("UnionPay sign with privateKey error: %v", err)
	}
	m["signature"] = sign
	log.Println("UnionPay sign: ", sign)
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
	c.apiaddr = "/gateway/api/appTransReq.do"
	m := make(map[string]string, 0)
	m["txnType"] = "01"
	m["txnSubType"] = "01"
	m["bizType"] = "000201"
	m["channelType"] = "08"
	m["accessType"] = "0"
	m["currencyCode"] = "156"

	m["orderId"] = orderNo
	m["txnAmt"] = fmt.Sprintf("%d", txnamt)
	if attach != "" {
		m["reqReserved"] = base64.StdEncoding.EncodeToString([]byte(attach))
	}
	return c.Post(c.publicParams(m))
}

// ConsumeUndo 消费撤销交易
func (c *UnionPay) ConsumeUndo(txnamt int, orderNo, queryID, attach string) (map[string]string, error) {
	c.apiaddr = "/gateway/api/backTransReq.do"
	m := make(map[string]string, 0)
	m["txnType"] = "31"
	m["txnSubType"] = "00"
	m["bizType"] = "000201"
	m["channelType"] = "07"
	m["accessType"] = "0"

	m["orderId"] = orderNo
	m["origQryId"] = queryID
	m["txnAmt"] = fmt.Sprintf("%d", txnamt)
	if attach != "" {
		m["reqReserved"] = base64.StdEncoding.EncodeToString([]byte(attach))
	}
	m["frontUrl"] = "0"
	return c.Post(c.publicParams(m))
}

// Refund 退货交易
func (c *UnionPay) Refund(txnamt int, orderNo, queryID, attach string) (map[string]string, error) {
	c.apiaddr = "/gateway/api/backTransReq.do"
	m := make(map[string]string, 0)
	m["txnType"] = "04"
	m["txnSubType"] = "00"
	m["bizType"] = "000201"
	m["channelType"] = "07"
	m["accessType"] = "0"

	m["orderId"] = orderNo
	m["origQryId"] = queryID
	m["txnAmt"] = fmt.Sprintf("%d", txnamt)
	if attach != "" {
		m["reqReserved"] = base64.StdEncoding.EncodeToString([]byte(attach))
	}
	m["frontUrl"] = "0"
	return c.Post(c.publicParams(m))
}

// Query 交易状态查询
func (c *UnionPay) Query(orderNo string) (map[string]string, error) {
	c.apiaddr = "/gateway/api/queryTrans.do"
	m := make(map[string]string, 0)
	m["txnType"] = "00"
	m["txnSubType"] = "00"
	m["bizType"] = "000000"
	m["channelType"] = "07"
	m["accessType"] = "0"

	m["orderId"] = orderNo
	m["frontUrl"] = "0"
	m["backUrl"] = "0"
	return c.Post(c.publicParams(m))
}
