#### 银联手机支付控件（含安卓Pay）SDK For Golang

![go 1.15](https://img.shields.io/badge/go-1.15-green) [![GitHub license](https://img.shields.io/github/license/mintaylor/unionpay)](https://github.com/mintaylor/unionpay/blob/master/LICENSE)

##### 安装

```golang
go get -u  github.com/mintaylor/unionpay
```

##### 初始化

```golang
 var pay = NewUnionPay{
  // 支付初始化参数
 }
// 仅使用Pfx私钥

```

##### 注意

* Pfx证书需在IE 10 以下版本导出，否则无法使用

* 预授权部分接口仅参数不同，[银联SDK详情地址](https://open.unionpay.com/tjweb/acproduct/list?apiSvcId=450&index=1)

* 后台通知的参数获取为Post form参数url转码后的字符串
  ```
  (txnType=01&version=5.1.0)
  ```
* 后台通知返回，银联以http状态码判断：商户返回码为200或302时，银联判定为通知成功，其他返回码为通知失败
