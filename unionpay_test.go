package unionpay

import (
	"testing"
)

// demo
var pay = &UnionPay{
	Mode:    "dev",
	MerID:   "777290058110048",
	PfxPath: "./cert/acp_test_sign.pfx",
	PfxPwd:  "000000",
	BackURL: "http://www.specialUrl.com",
}

func TestAppConsume(t *testing.T) {
	if err := pay.New(); err != nil {
		t.Fatalf("new unionpay error: %v", err)
	}

	amount := "1000"
	orderId := "2020091616504012"
	result, err := pay.AppConsume(amount, orderId, "test")
	if err != nil {
		t.Error(err)
		return
	}

	t.Logf("merId: %v,orderId: %v,Tn: %v", result["merId"], result["orderId"], result["tn"])
}

func TestQuery(t *testing.T) {
	if err := pay.New(); err != nil {
		t.Fatalf("new unionpay error: %v", err)
	}

	orderId := "2020091616504012"
	result, err := pay.Query(orderId)
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(result)
}
