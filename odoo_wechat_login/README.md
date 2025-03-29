# 微信登录整合说明

### 这是参照官方微信文档整理的登录流程总结。

### 更详细的获取用户数据等流程可以参考 [微信登录文档](https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html)。

## 第一步：请求 CODE

#### 使用应用的 appid 和一些静态参数换取用户授权后返回的 code。

### 跳转至微信扫码页面

#### 用户访问以下链接后，会看到微信扫码登录页面：

`https://open.weixin.qq.com/connect/qrconnect?
    appid=wxbdc5610cc59c1631&
    redirect_uri=https%3A%2F%2Fpassport.yhd.com%2Fwechat%2Fcallback.do&
    response_type=code&
    scope=snsapi_login&
    state=a4df54aa7eecaad018bbda169bd6bc12
    #wechat_redirect`

### 用户扫码后自动跳转至确认页面

#### 扫码后，微信会自动重定向到类似下面的 URL：

`https://passport.yhd.com/wechat/callback.do?
    code=CODE&
    state=3d6be0a4035d839573b04816624a415e`

## 第二步：通过 CODE 获取 access_token

#### 通过调用以下接口，使用 appid、appsecret 以及上一步返回的 code 来换取 access_token、openid 等信息。

`https://api.weixin.qq.com/sns/oauth2/access_token?
    appid=APPID&
    secret=SECRET&
    code=CODE&
    grant_type=authorization_code`

请根据您的实际情况替换上述 URL 中的参数（如 APPID、SECRET 和 CODE 等）。
更多详细说明请参阅官方文档：微信登录文档。