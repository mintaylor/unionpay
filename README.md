#### 银联手机支付控件（含安卓Pay）SDK For Golang

> 将20年当时修改后的代码提交上来了...

##### 安装

```golang
go get -u  github.com/mintaylor/unionpay
```

##### 初始化

```golang
pay := &UnionPay{
  // 支付初始化参数
}

if err := pay.New(); err != nil {
  log.Fatalf("new unionpay error: %v", err)
}
```

##### 注意

* 仅使用Pfx私钥，Pfx证书需在IE 10 以下版本导出，否则无法使用
* 预授权部分接口仅参数不同，可根据需要添加:
  [银联线上收银台（微信支付宝专用版）](https://open.unionpay.com/tjweb/acproduct/list?apiSvcId=450)
  [银联线上收银台（通用版）](https://open.unionpay.com/tjweb/acproduct/list?apiSvcId=3021)
* 后台通知的参数获取为Post form参数url转码后的字符串
  ```
  (txnType=01&version=5.1.0 ...)
  ```
* 后台通知返回，银联以http状态码判断：商户返回码为200或302时，银联判定为通知成功，其他返回码为通知失败
