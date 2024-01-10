package unionpay

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	Version    = "5.1.0"
	Encoding   = "utf-8"
	SignMethod = "01" // 01: RSA

	EnvProd     = "prod"
	EnvDev      = "dev"
	GatewayProd = "https://gateway.95516.com"
	GatewayDev  = "https://gateway.test.95516.com"

	appTransAddr   = "/gateway/api/appTransReq.do"
	backTransAddr  = "/gateway/api/backTransReq.do"
	queryTransAddr = "/gateway/api/queryTrans.do"

	TxnTimeFormat = "20060102150405"

	ContentTypeForm = "application/x-www-form-urlencoded;charset=utf-8"
)

// UnionPay unionpay
type UnionPay struct {
	Mode     string
	MerID    string
	FrontURL string
	BackURL  string
	PfxPath  string
	PfxPwd   string

	unionCert struct {
		Private *rsa.PrivateKey
		Cert    *x509.Certificate
		CertID  string
	}

	httpClient *http.Client
}

// New new unionpay client.
func (c *UnionPay) New() error {
	if err := c.CheckConfig(); err != nil {
		return err
	}

	c.httpClient = &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	return nil
}

// CheckConfig check config
func (c *UnionPay) CheckConfig() error {
	if c.MerID == "" {
		return errors.New("checkConfig error: MerID is empty")
	}
	if c.PfxPath == "" {
		return errors.New("checkConfig error: PfxPath is empty")
	}
	if c.PfxPwd == "" {
		return errors.New("checkConfig error: PfxPwd is empty")
	}
	if c.Mode == "" {
		return errors.New("checkConfig error: Mode is empty")
	}
	if c.Mode != "dev" && c.Mode != "prod" {
		return errors.New("checkConfig error: invalid Mode")
	}

	var err error
	c.unionCert.Private, c.unionCert.Cert, err = ParserPfxToCert(c.PfxPath, c.PfxPwd)
	if err != nil {
		return errors.New("checkConfig error: failed to parse PFX certificate")
	}

	c.unionCert.CertID = c.unionCert.Cert.SerialNumber.String()
	return nil
}

// getAPIURL get api url
func (c *UnionPay) getAPIURL(addr string) string {
	if c.Mode == EnvProd {
		return GatewayProd + addr
	}

	return GatewayDev + addr
}

// Request request
func (c *UnionPay) Request(addr string, extraParams map[string]string) (map[string]string, error) {
	reqUrl := c.getAPIURL(addr)
	params := c.prepParams(addr, extraParams)
	// gen sign
	params, err := c.genSign(params)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(reqUrl, ContentTypeForm, strings.NewReader(MapToQuery(params)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http request response StatusCode:%v", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	result := c.splitToMap(string(respBytes))

	if err = c.resultCheck(result); err != nil {
		return nil, err
	}

	return result, nil
}

// resultCheck check result code and sign.
func (c *UnionPay) resultCheck(m map[string]string) error {
	if m["respCode"] != "00" {
		return fmt.Errorf("result check error: code %s, message %s", m["respCode"], m["respMsg"])
	}

	// check sign
	if err := SignVerify(m); err != nil {
		return err
	}

	return nil
}

// splitToMap split string to map.
func (c *UnionPay) splitToMap(data string) map[string]string {
	values := strings.Split(data, "&")
	m := make(map[string]string, len(values))

	for _, v := range values {
		kv := strings.SplitN(v, "=", 2)
		m[kv[0]] = kv[1]
	}

	return m
}

// ParseNotify parse and url decode notification.
func (c *UnionPay) ParseNotify(data string) (map[string]string, error) {
	data, err := url.QueryUnescape(data)
	if err != nil {
		return nil, err
	}

	return c.splitToMap(data), nil
}

// SortUnionMap sort map
func SortUnionMap(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	str := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != "signature" {
			str = append(str, k+"="+m[k])
		}
	}
	return strings.Join(str, "&")
}

// MapToQuery map to url query
func MapToQuery(m map[string]string) string {
	query := url.Values{}
	for key, value := range m {
		query.Set(key, value)
	}
	return query.Encode()
}

// genSign gen sign
func (c *UnionPay) genSign(m map[string]string) (map[string]string, error) {
	sign, err := SignMapWithPrivate(m, c.unionCert.Private)
	if err != nil {
		return nil, fmt.Errorf("UnionPay sign with privateKey error: %v", err)
	}

	m["signature"] = sign
	return m, nil
}

// prepParams prep params
func (c *UnionPay) prepParams(addr string, m map[string]string) map[string]string {
	// add public params
	m["merId"] = c.MerID
	m["version"] = Version
	m["encoding"] = Encoding
	m["signMethod"] = SignMethod
	m["certId"] = c.unionCert.CertID
	m["txnTime"] = time.Now().Format(TxnTimeFormat)
	m["accessType"] = "0"   // 0：商户直连接入
	m["bizType"] = "000201" // 000201：B2C网关支付

	// check encoding params
	if value, ok := m["reqReserved"]; ok && value != "" {
		m["reqReserved"] = base64.StdEncoding.EncodeToString([]byte(value))
	}

	// check addr need params
	switch addr {
	case appTransAddr:
		if c.FrontURL != "" {
			m["frontUrl"] = c.FrontURL
		}
	}

	return m
}

// AppConsume 消费获取Tn
func (c *UnionPay) AppConsume(txnamt, orderNo, attach string) (map[string]string, error) {
	m := map[string]string{
		"txnType":      "01",
		"txnSubType":   "01",
		"channelType":  "08",
		"currencyCode": "156",
		"orderId":      orderNo,
		"txnAmt":       txnamt,
		"backUrl":      c.BackURL,
		"reqReserved":  attach,
	}

	return c.Request(appTransAddr, m)
}

// ConsumeUndo 消费撤销交易
func (c *UnionPay) ConsumeUndo(txnamt, orderNo, queryID, attach string) (map[string]string, error) {
	m := map[string]string{
		"txnType":     "31",
		"txnSubType":  "00",
		"channelType": "07",
		"orderId":     orderNo,
		"origQryId":   queryID,
		"txnAmt":      txnamt,
		"backUrl":     c.BackURL,
		"reqReserved": attach,
	}

	return c.Request(backTransAddr, m)
}

// Refund 退货交易
func (c *UnionPay) Refund(txnamt, orderNo, queryID, attach string) (map[string]string, error) {
	m := map[string]string{
		"txnType":     "04",
		"txnSubType":  "00",
		"channelType": "07",
		"orderId":     orderNo,
		"origQryId":   queryID,
		"txnAmt":      txnamt,
		"backUrl":     c.BackURL,
		"reqReserved": attach,
	}

	return c.Request(backTransAddr, m)
}

// Query 交易状态查询
func (c *UnionPay) Query(orderNo string) (map[string]string, error) {
	m := map[string]string{
		"txnType":    "00",
		"txnSubType": "00",
		"bizType":    "000000",
		"orderId":    orderNo,
	}

	return c.Request(queryTransAddr, m)
}
